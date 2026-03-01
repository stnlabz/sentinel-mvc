<?php
// path: /app/controllers/sentinel.php

class sentinel extends controller 
{
    /**
     * Autonomous Firewall Inspector.
     * Static context for Bootstrap integration to ensure zero-latency blocking.
     */
    public static function inspect(): void 
    {
        // Manual model instantiation to avoid $this->model in static context [cite: 2026-02-20]
        require_once APPROOT . '/models/sentinel_model.php';
        $model = new sentinel_model();
        $config = $model->get_config_map();
        
        // 1. Autonomous Background Sync (Hourly)
        $last_sync = (int)($config['last_sync_time'] ?? 0);
        if ((time() - $last_sync) > 3600) {
            $model->pull_global_intelligence();
            $config = $model->get_config_map(); 
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';

        // 2. Silent Block: Immediate termination if IP is blacklisted
        if ($model->is_blocked($ip)) {
            self::terminate_request("IP Blocked by Sentinel Global Intel");
        }

        // 3. Pattern Matching: Auto-blocking malicious URI strings
        $patterns = explode(',', $config['malicious_patterns'] ?? '');
        foreach ($patterns as $pattern) {
            $p = trim($pattern);
            if (!empty($p) && stripos($uri, $p) !== false) {
                $model->log_threat($ip, 'pattern_match', $uri);
                $model->block_ip($ip);
                self::terminate_request("Threat Pattern Detected: " . $p);
            }
        }
    }

    /**
     * Static Termination: Replaces the non-static block_request to allow bootstrap calls.
     */
    private static function terminate_request($reason): void 
    {
        http_response_code(403);
        die("<h3>sentinel security</h3><p>access denied: " . htmlspecialchars($reason) . "</p>");
    }

    /**
     * Admin Interface: Standard non-static method for dashboard management.
     */
    public function admin($url = []): void
    {
        // Restricted to level 9 (Highest Office) [cite: 2026-02-20]
        if (!isset($_SESSION['user_level']) || $_SESSION['user_level'] < 9) {
            header("Location: /admin");
            exit;
        }

        $model = $this->model('sentinel_model');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
            // Update configuration or manually block an IP
            if ($action === 'update_config') { $model->save_config($_POST['settings']); }
            if ($action === 'block_ip') { $model->block_ip($_POST['ip']); }
            header("Location: /admin/sentinel");
            exit;
        }

        $data['api_intel'] = $model->pull_global_intelligence();
        $data['events'] = $model->get_recent_events();
        $data['config_map'] = $model->get_config_map();
        
        $this->view('admin/sentinel', $data);
    }
}
