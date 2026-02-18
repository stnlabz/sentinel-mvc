<?php require APPROOT . '/views/inc/head.php'; ?>

<div class="container py-5">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="fw-bold mb-0">Sentinel Security</h2>
            <p class="text-muted small text-uppercase font-monospace">Live Intelligence & Threat Oversight</p>
        </div>
        <div class="d-flex gap-2">
            <div class="badge bg-dark text-white border p-2 font-monospace">
                API Version: <?= $data['api_intel']['version'] ?? '1.8.0'; ?>
            </div>
            <div class="badge bg-light text-dark border p-2">
                Status: <span class="text-success font-monospace">Monitoring</span>
            </div>
        </div>
    </div>

    <?php if (isset($data['api_intel']['analysis'])): ?>
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card shadow-sm border-0 bg-primary text-white">
                <div class="card-body">
                    <h6 class="small text-uppercase fw-bold opacity-75">Global Velocity (24h)</h6>
                    <h2 class="fw-bold"><?= $data['api_intel']['analysis']['total_24h'] ?? 0; ?></h2>
                    <p class="mb-0 x-small">Threats across all nodes in the Last 24 Hours.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card shadow-sm border-0 border-start border-4 border-warning">
                <div class="card-body">
                    <h6 class="small text-uppercase fw-bold text-muted">Top Trending Pattern</h6>
                    <?php 
                        $trends = $data['api_intel']['analysis']['trending'] ?? [];
                        $top = !empty($trends) ? array_key_first($trends) : 'None';
                    ?>
                    <h4 class="fw-bold text-warning mb-1"><?= htmlspecialchars($top); ?></h4>
                    <p class="mb-0 x-small text-muted">Currently spiking in the global feed.</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card shadow-sm border-0 border-start border-4 border-info">
                <div class="card-body">
                    <h6 class="small text-uppercase fw-bold text-muted">Active Node Impact</h6>
                    <?php 
                        $impact = $data['api_intel']['analysis']['active_sites'] ?? [];
                        $count = count($impact);
                    ?>
                    <h4 class="fw-bold text-info mb-1"><?= $count; ?> Sites</h4>
                    <p class="mb-0 x-small text-muted">Business nodes currently under probe.</p>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <form action="/admin/sentinel" method="POST">
        <input type="hidden" name="action" value="update_config">
        
        <div class="row">
            <div class="col-md-5">
                <div class="card shadow-sm mb-4 border-0">
                    <div class="card-header bg-dark text-white py-3">
                        <h6 class="mb-0 small text-uppercase fw-bold">Global Identity & API</h6>
                    </div>
                    <div class="card-body border">
                        <div class="mb-3">
                            <label class="form-label small fw-bold text-muted text-uppercase">Permanent Site ID</label>
                            <input type="text" class="form-control bg-light font-monospace" 
                                   value="<?= $data['config_map']['site_id'] ?? 'site_75663fa85281c37a'; ?>" readonly>
                            <div class="form-text x-small text-info mt-1">Locked for STN-Labz reporting.</div>
                        </div>

                        <div class="mb-0">
                            <label class="form-label small fw-bold text-uppercase">API Key</label>
                            <input type="password" name="settings[api_key]" class="form-control font-monospace" 
                                   value="<?= $data['config_map']['api_key'] ?? ''; ?>" placeholder="stn_v1_...">
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-7">
                <div class="card shadow-sm mb-4 border-0">
                    <div class="card-header bg-white border py-3">
                        <h6 class="mb-0 fw-bold small text-uppercase">Live Firewall Rules</h6>
                    </div>
                    <div class="card-body border border-top-0">
                        <div class="mb-3">
                            <label class="form-label small fw-bold text-uppercase">Malicious Patterns (Dynamic)</label>
                            <textarea name="settings[malicious_patterns]" class="form-control font-monospace" rows="4" 
                                      placeholder="wp-admin, .env, xmlrpc"><?= $data['config_map']['malicious_patterns'] ?? ''; ?></textarea>
                            <div class="form-text x-small mt-1 text-muted">Auto-enriched by global API trends.</div>
                        </div>
                        <div class="text-end">
                            <button type="submit" class="btn btn-primary btn-sm px-4">Update Sentinel Config</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </form>

    <div class="card shadow-sm border-0">
        <div class="card-header bg-white border py-3 text-uppercase small fw-bold d-flex justify-content-between">
            <span>Recent Interceptions</span>
            <span class="text-muted font-monospace" style="font-size: 10px;">Sync: <?= date('H:i:s'); ?></span>
        </div>
        <div class="card-body p-0 border border-top-0">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light x-small text-muted text-uppercase">
                        <tr>
                            <th class="ps-4">Timestamp</th>
                            <th>IP Address</th>
                            <th>Category</th>
                            <th>Target Domain</th>
                            <th>Status</th>
                            <th class="text-end pe-4">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(empty($data['events'])): ?>
                            <tr><td colspan="6" class="text-center py-5 text-muted">No threats detected yet.</td></tr>
                        <?php else: ?>
                            <?php foreach($data['events'] as $event): ?>
                            <tr>
                                <td class="ps-4 small text-muted font-monospace"><?= $event['timestamp']; ?></td>
                                <td><code><?= $event['ip_address']; ?></code></td>
                                <td>
                                    <span class="badge bg-warning-subtle text-warning border border-warning-subtle x-small">
                                        <?= str_replace('_', ' ', $event['threat_category']); ?>
                                    </span>
                                </td>
                                <td class="small text-muted"><?= $event['domain'] ?? 'N/A'; ?></td>
                                <td>
                                    <span class="badge <?= $event['status'] === 'blocked' ? 'bg-danger' : 'bg-secondary'; ?> rounded-pill x-small">
                                        <?= strtoupper($event['status']); ?>
                                    </span>
                                </td>
                                <td class="text-end pe-4">
                                    <i class="bi bi-shield-lock-fill text-success"></i>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php require APPROOT . '/views/inc/foot.php'; ?>
