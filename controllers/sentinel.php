<?php
// path: /app/controllers/sentinel.php

class sentinel extends controller 
{
    /**
     * Autonomous Firewall Inspector.
     * Performs Background Hourly Sync and Real-time Blocking.
     */
    public static function inspect(): void 
    {
        $model = $this->model('sentinel_model');
        $config = $model->get_config_map();
        
        // 1. Autonomous Background Sync (Hourly selling point)
        $last_sync = (int)($config['last_sync_time'] ?? 0);
        if ((time() - $last_sync) > 3600) {
            $model->pull_global_intelligence();
            $config = $model->get_config_map(); 
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';

        // 2. Silent Block: Checks local DB status and terminates if already blocked
        if ($model->is_blocked($ip)) {
            $this->block_request("IP Blocked by Sentinel Global Intel");
        }

        // 3. Pattern Matching with Auto-Block and Global Telemetry
        $patterns = explode(',', $config['malicious_patterns'] ?? '');
        foreach ($patterns as $pattern) {
            $p = trim($pattern);
            if (!empty($p) && stripos($uri, $p) !== false) {
                $model->log_threat($ip, 'pattern_match', $uri);
                $model->block_ip($ip);
                $this->block_request("Threat Pattern Detected: " . $p);
            }
        }
    }

    private function block_request($reason): void 
    {
        http_response_code(403);
        die("<h3>sentinel security</h3><p>access denied: " . htmlspecialchars($reason) . "</p>");
    }

    public function admin($url = []): void
    {
        if (!isset($_SESSION['user_level']) || $_SESSION['user_level'] < 9) {
            header("Location: /admin");
            exit;
        }

        $model = $this->model('sentinel_model');

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
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
