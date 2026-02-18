<?php
// path: /app/models/sentinel_model.php

class sentinel_model extends model 
{
    private $api_url = 'https://api.stn-labz.com/v1/intel';

    /**
     * Checks if an IP is permanently blocked.
     */
    public function is_blocked($ip): bool 
    {
        $row = $this->query("SELECT status FROM sentinel WHERE ip_address = ? AND status = 'blocked' LIMIT 1", [$ip])->fetch();
        return $row ? true : false;
    }

    /**
     * Permanent block to stop redundant processing and log spam.
     */
    public function block_ip($ip): void 
    {
        $this->query("UPDATE sentinel SET status = 'blocked' WHERE ip_address = ?", [$ip]);
        $this->query("INSERT IGNORE INTO sentinel (ip_address, threat_category, status) VALUES (?, 'auto_block', 'blocked')", [$ip]);
    }

    /**
     * Pulls Global Intelligence using the widget's fetch logic.
     * Prevents IP duplication across categories.
     */
    public function pull_global_intelligence(): array 
    {
        $config = $this->get_config_map();
        $api_key = $config['api_key'] ?? '';
        
        if (empty($api_key)) return [];

        // Fetching using the logic proven in widget.php
        $ch = curl_init($this->api_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-API-KEY: ' . $api_key]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $response = curl_exec($ch);
        curl_close($ch);

        $data = json_decode((string)$response, true);

        if (is_array($data)) {
            // 1. Update Patterns from trending 'by_type' data
            $new_patterns = $data['patterns'] ?? [];
            if (!empty($data['stats']['by_type'])) {
                $trending = array_keys($data['stats']['by_type']);
                $new_patterns = array_unique(array_merge($new_patterns, $trending));
            }

            if (!empty($new_patterns)) {
                $current_raw = $config['malicious_patterns'] ?? '';
                $current_arr = array_filter(array_map('trim', explode(',', $current_raw)));
                $merged = array_unique(array_merge($current_arr, $new_patterns));
                $this->save_config(['malicious_patterns' => implode(',', $merged)]);
            }

            // 2. Strict IP Sync: Only inserts if the IP doesn't exist in ANY category
            if (!empty($data['blocklists']['ips']) && is_array($data['blocklists']['ips'])) {
                foreach ($data['blocklists']['ips'] as $ip) {
                    $exists = $this->query("SELECT id FROM sentinel WHERE ip_address = ? LIMIT 1", [$ip])->fetch();
                    if (!$exists) {
                        $this->query("INSERT INTO sentinel (ip_address, threat_category, status) VALUES (?, 'global_sync', 'blocked')", [$ip]);
                    }
                }
            }
            
            $this->save_config(['last_sync_time' => time()]);
            return $data;
        }

        return [];
    }

    /**
     * Telemetry Sync: site_id is flattened at the root.
     * This allows the API to recognize the reporting plugin.
     */
    public function log_threat($ip, $category, $url): void 
    {
        $config = $this->get_config_map();
        $this->query("INSERT INTO sentinel (ip_address, threat_category, request_url, status) VALUES (?, ?, ?, 'blocked')", [$ip, $category, $url]);

        if (!empty($config['api_key'])) {
            $payload = json_encode([
                'source'  => 'sentinel',
                'site_id' => $config['site_id'], // Root-level for API aggregation
                'type'    => $category,
                'details' => [
                    'request_url' => $url,
                    'ip_address'  => $ip,
                    'domain'      => $_SERVER['HTTP_HOST'] ?? 'unknown'
                ]
            ]);

            $ch = curl_init('https://api.stn-labz.com/v1/threats');
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'X-API-KEY: ' . $config['api_key']]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 2);
            curl_exec($ch);
            curl_close($ch);
        }
    }

    public function get_recent_events(): array { return $this->query("SELECT * FROM sentinel ORDER BY timestamp DESC LIMIT 100")->fetchAll(); }
    public function save_config($settings): void { foreach($settings as $k => $v) { $this->query("INSERT INTO sentinel_config (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?", [$k, $v, $v]); } }
    
    public function get_config_map(): array 
    {
        $raw = $this->query("SELECT setting_key, setting_value FROM sentinel_config")->fetchAll();
        $map = [];
        foreach ($raw as $row) { $map[$row['setting_key']] = $row['setting_value']; }
        if (empty($map['site_id'])) {
            $new_id = 'site_' . substr(md5($_SERVER['HTTP_HOST'] ?? 'unknown'), 0, 16);
            $this->save_config(['site_id' => $new_id]);
            $map['site_id'] = $new_id;
        }
        return $map;
    }
}
