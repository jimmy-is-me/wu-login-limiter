<?php
/**
 * Plugin Name: WU Login Limiter
 * Plugin URI:  https://wumetax.com
 * Description: 限制登入嘗試次數、IP 黑白名單與自動封鎖高頻 IP 的安全外掛。
 * Version:     1.0.2
 * Author:      wumetax
 * Author URI:  https://wumetax.com
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wu-login-limiter
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class WU_Login_Limiter {

    private $table_name;
    private $settings_option_name = 'wu_login_limiter_settings';
    private $settings;
    private $cache_group = 'wu_login_limiter';

    // 嘗試計算的時間窗（分鐘），抽成常數方便日後改成設定項
    const ATTEMPT_WINDOW_MINUTES = 60;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wu_login_attempts';
        $this->settings   = get_option( $this->settings_option_name, $this->get_default_settings() );

        register_activation_hook( __FILE__, array( $this, 'activate_plugin' ) );
        register_deactivation_hook( __FILE__, array( $this, 'deactivate_plugin' ) );

        add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_plugin_action_links' ) );

        add_action( 'wp_login_failed', array( $this, 'log_failed_attempt' ) );
        add_action( 'wp_login', array( $this, 'clear_failed_attempts' ), 10, 2 );
        add_filter( 'authenticate', array( $this, 'check_ip_blocked' ), 30, 3 );
        add_filter( 'wp_login_errors', array( $this, 'customize_error_message' ) );
        add_action( 'login_enqueue_scripts', array( $this, 'add_login_page_info' ) );

        add_action( 'wp_loaded', array( $this, 'schedule_cleanup' ) );
        add_action( 'wu_login_limiter_cleanup', array( $this, 'cleanup_old_records' ) );
    }

    private function get_default_settings() {
        return array(
            'enabled'                => false,
            'max_attempts'           => 3,
            'max_locks'              => 3,
            'lock_duration'          => 1800,
            'extended_lock_duration' => 86400,
            'log_attempts'           => true,
            'whitelist'              => array(),
            'blacklist'              => array(),
            'auto_ban_enabled'       => true,
            'auto_ban_threshold'     => 50,
            'auto_ban_window_hours'  => 1,
        );
    }

    public function activate_plugin() {
        $this->init_database();
        if ( ! wp_next_scheduled( 'wu_login_limiter_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wu_login_limiter_cleanup' );
        }
    }

    public function deactivate_plugin() {
        $timestamp = wp_next_scheduled( 'wu_login_limiter_cleanup' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wu_login_limiter_cleanup' );
        }
    }

    public function init_database() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id int(11) NOT NULL AUTO_INCREMENT,
            ip varchar(45) NOT NULL,
            username varchar(60) NOT NULL,
            attempt_time datetime DEFAULT CURRENT_TIMESTAMP,
            blocked_until datetime NULL,
            lock_count int(11) DEFAULT 0,
            is_blocked tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY ip (ip),
            KEY blocked_until (blocked_until)
        ) $charset_collate;";
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public function add_settings_page() {
        add_options_page(
            '登入嘗試限制',
            '登入嘗試限制',
            'manage_options',
            'wu-login-limiter',
            array( $this, 'settings_page_html' )
        );
    }

    public function add_plugin_action_links( $links ) {
        $settings_link = '<a href="' . admin_url( 'options-general.php?page=wu-login-limiter' ) . '">設定</a>';
        array_unshift( $links, $settings_link );
        return $links;
    }

    // ✅ 修正：正確處理 textarea 換行，相容 \r\n / \n / \r
    private function normalize_ip_list( $raw ) {
        $raw = str_replace( "\r\n", "\n", (string) $raw );
        $raw = str_replace( "\r",   "\n", $raw );
        return array_values( array_filter( array_map( 'trim', explode( "\n", $raw ) ) ) );
    }

    public function settings_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) return;

        if ( isset( $_POST['wu_login_limiter_save'] ) ) {
            $this->save_settings();
        }
        if ( isset( $_POST['clear_logs'] ) ) {
            $this->clear_all_logs();
        }
        if ( isset( $_POST['unblock_ip'], $_POST['ip_to_unblock'] ) ) {
            $this->unblock_ip( sanitize_text_field( $_POST['ip_to_unblock'] ) );
        }

        $this->settings = get_option( $this->settings_option_name, $this->get_default_settings() );
        $recent_attempts = $this->get_recent_attempts();
        $blocked_ips     = $this->get_blocked_ips();

        // ✅ 修正：使用雙引號 "\n"（真正換行），而非 "\\n"（字面兩字元）
        $whitelist_textarea = implode( "\n", (array) $this->settings['whitelist'] );
        $blacklist_textarea = implode( "\n", (array) $this->settings['blacklist'] );
        ?>
        <div class="wrap">
            <h1>登入嘗試限制設定</h1>

            <form method="post" action="">
                <?php wp_nonce_field( 'wu_login_limiter_settings' ); ?>

                <h2 class="title">基本設定</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">啟用功能</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $this->settings['enabled'] ) ); ?>>
                                啟用登入嘗試限制
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">最大失敗次數</th>
                        <td>
                            <input type="number" name="max_attempts" value="<?php echo esc_attr( $this->settings['max_attempts'] ); ?>" min="1" max="20">
                            <p class="description">首次阻擋前允許的失敗次數（預設：3）。計算時間窗為 <?php echo self::ATTEMPT_WINDOW_MINUTES; ?> 分鐘。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">最大鎖定次數</th>
                        <td>
                            <input type="number" name="max_locks" value="<?php echo esc_attr( $this->settings['max_locks'] ); ?>" min="1" max="10">
                            <p class="description">超過此鎖定次數後改用延長鎖定（預設：3）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">普通鎖定時間（秒）</th>
                        <td>
                            <input type="number" name="lock_duration" value="<?php echo esc_attr( $this->settings['lock_duration'] ); ?>" min="300" max="86400">
                            <p class="description">普通鎖定持續時間（預設：1800 秒 = 30 分鐘）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">延長鎖定時間（秒）</th>
                        <td>
                            <input type="number" name="extended_lock_duration" value="<?php echo esc_attr( $this->settings['extended_lock_duration'] ); ?>" min="3600" max="604800">
                            <p class="description">延長鎖定持續時間（預設：86400 秒 = 24 小時）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">記錄失敗嘗試</th>
                        <td>
                            <label>
                                <input type="checkbox" name="log_attempts" value="1" <?php checked( ! empty( $this->settings['log_attempts'] ) ); ?>>
                                記錄所有失敗的登入嘗試
                            </label>
                        </td>
                    </tr>
                </table>

                <h2 class="title">IP 名單設定</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">IP 白名單</th>
                        <td>
                            <textarea name="whitelist" rows="5" cols="50" placeholder="每行一個IP或網段，例如：&#10;192.168.1.1&#10;10.0.0.0/8"><?php echo esc_textarea( $whitelist_textarea ); ?></textarea>
                            <p class="description">白名單中的 IP 不會被阻擋。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">IP 黑名單（永久阻擋）</th>
                        <td>
                            <textarea name="blacklist" rows="5" cols="50" placeholder="每行一個IP或網段，例如：&#10;192.168.1.100&#10;203.0.113.0/24"><?php echo esc_textarea( $blacklist_textarea ); ?></textarea>
                            <p class="description">黑名單中的 IP 會被永久阻擋。自動封鎖的 IP 也會顯示在此。</p>
                        </td>
                    </tr>
                </table>

                <h2 class="title">自動永久封鎖高頻 IP</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">啟用自動封鎖</th>
                        <td>
                            <label>
                                <input type="checkbox" name="auto_ban_enabled" value="1" <?php checked( ! empty( $this->settings['auto_ban_enabled'] ) ); ?>>
                                依照失敗次數自動永久封鎖高頻 IP
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">時間窗（小時）</th>
                        <td>
                            <input type="number" name="auto_ban_window_hours" value="<?php echo esc_attr( $this->settings['auto_ban_window_hours'] ); ?>" min="1" max="168">
                            <p class="description">在此時間內累積失敗達閾值即永久封鎖（預設：1 小時）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">失敗次數閾值</th>
                        <td>
                            <input type="number" name="auto_ban_threshold" value="<?php echo esc_attr( $this->settings['auto_ban_threshold'] ); ?>" min="10" max="10000">
                            <p class="description">達到此失敗次數就自動加入黑名單（預設：50）。</p>
                        </td>
                    </tr>
                </table>

                <?php submit_button( '儲存設定', 'primary', 'wu_login_limiter_save' ); ?>
            </form>

            <hr>

            <h2>統計資訊</h2>
            <div style="display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;">
                <div style="background:#f9f9f9;padding:15px;border-radius:5px;">
                    <strong>總失敗嘗試次數：</strong><?php echo intval( $this->get_total_attempts() ); ?>
                </div>
                <div style="background:#f9f9f9;padding:15px;border-radius:5px;">
                    <strong>目前被暫時阻擋的 IP：</strong><?php echo count( $blocked_ips ); ?>
                </div>
                <div style="background:#f9f9f9;padding:15px;border-radius:5px;">
                    <strong>黑名單 IP 數量：</strong><?php echo count( (array) $this->settings['blacklist'] ); ?>
                </div>
                <div style="background:#f9f9f9;padding:15px;border-radius:5px;">
                    <strong>24 小時內嘗試：</strong><?php echo intval( $this->get_attempts_in_period( 24 ) ); ?>
                </div>
            </div>

            <?php if ( ! empty( $blocked_ips ) ) : ?>
            <h3>目前被暫時阻擋的 IP</h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>IP 位址</th>
                        <th>阻擋到期時間</th>
                        <th>鎖定次數</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $blocked_ips as $row ) : ?>
                    <tr>
                        <td><?php echo esc_html( $row->ip ); ?></td>
                        <td><?php echo esc_html( $row->blocked_until ); ?></td>
                        <td><?php echo esc_html( $row->lock_count ); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field( 'wu_login_limiter_settings' ); ?>
                                <input type="hidden" name="ip_to_unblock" value="<?php echo esc_attr( $row->ip ); ?>">
                                <input type="submit" name="unblock_ip" value="解除阻擋" class="button-secondary"
                                    onclick="return confirm('確定要解除此 IP 的阻擋嗎？（也會從黑名單移除）');">
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>

            <h3>最近的登入嘗試</h3>
            <form method="post" style="margin:10px 0;">
                <?php wp_nonce_field( 'wu_login_limiter_settings' ); ?>
                <input type="submit" name="clear_logs" value="清除所有日誌" class="button-secondary"
                    onclick="return confirm('確定要清除所有登入嘗試日誌嗎？');">
            </form>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>時間</th>
                        <th>IP 位址</th>
                        <th>用戶名</th>
                        <th>狀態</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $recent_attempts ) ) : ?>
                    <tr><td colspan="4">暫無登入嘗試記錄</td></tr>
                    <?php else : ?>
                        <?php foreach ( $recent_attempts as $attempt ) : ?>
                        <tr>
                            <td><?php echo esc_html( $attempt->attempt_time ); ?></td>
                            <td><?php echo esc_html( $attempt->ip ); ?></td>
                            <td><?php echo esc_html( $attempt->username ); ?></td>
                            <td>
                                <?php if ( $attempt->is_blocked ) : ?>
                                    <span style="color:red;">已阻擋</span>
                                <?php else : ?>
                                    <span style="color:orange;">失敗</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <style>
        .form-table th { width: 220px; }
        .wp-list-table { margin-top: 10px; }
        </style>
        <?php
    }

    private function save_settings() {
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wu_login_limiter_settings' ) ) {
            wp_die( '安全驗證失敗' );
        }

        $settings = array(
            'enabled'                => isset( $_POST['enabled'] ),
            'max_attempts'           => max( 1, intval( $_POST['max_attempts'] ?? 3 ) ),
            'max_locks'              => max( 1, intval( $_POST['max_locks'] ?? 3 ) ),
            'lock_duration'          => max( 300, intval( $_POST['lock_duration'] ?? 1800 ) ),
            'extended_lock_duration' => max( 3600, intval( $_POST['extended_lock_duration'] ?? 86400 ) ),
            'log_attempts'           => isset( $_POST['log_attempts'] ),
            // ✅ 使用抽出的 normalize_ip_list() 方法，確保換行正確
            'whitelist'              => $this->normalize_ip_list( $_POST['whitelist'] ?? '' ),
            'blacklist'              => $this->normalize_ip_list( $_POST['blacklist'] ?? '' ),
            'auto_ban_enabled'       => isset( $_POST['auto_ban_enabled'] ),
            'auto_ban_threshold'     => max( 10, intval( $_POST['auto_ban_threshold'] ?? 50 ) ),
            'auto_ban_window_hours'  => max( 1, intval( $_POST['auto_ban_window_hours'] ?? 1 ) ),
        );

        update_option( $this->settings_option_name, $settings );
        $this->settings = $settings;

        // 儲存設定後清除黑白名單快取
        wp_cache_flush_group( $this->cache_group );

        echo '<div class="notice notice-success is-dismissible"><p>設定已儲存！</p></div>';
    }

    public function log_failed_attempt( $username ) {
        if ( empty( $this->settings['enabled'] ) || empty( $this->settings['log_attempts'] ) ) return;

        $ip = $this->get_client_ip();

        if ( $this->is_ip_whitelisted( $ip ) ) return;

        global $wpdb;

        $wpdb->insert(
            $this->table_name,
            array(
                'ip'           => $ip,
                'username'     => sanitize_text_field( $username ),
                'attempt_time' => current_time( 'mysql' ),
                'is_blocked'   => 0,
            ),
            array( '%s', '%s', '%s', '%d' )
        );

        $this->check_and_block_ip( $ip );
        $this->check_and_auto_ban_ip( $ip );

        // 清除該 IP 的阻擋快取
        wp_cache_delete( 'wu_blocked_' . md5( $ip ), $this->cache_group );
    }

    private function check_and_block_ip( $ip ) {
        global $wpdb;

        // ✅ 使用 ATTEMPT_WINDOW_MINUTES 常數，避免硬寫死
        $recent_attempts = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name}
                 WHERE ip = %s
                 AND is_blocked = 0
                 AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
                $ip,
                self::ATTEMPT_WINDOW_MINUTES
            )
        );

        if ( $recent_attempts < $this->settings['max_attempts'] ) return;

        // ✅ 加 is_blocked = 1 條件，避免取到 0
        $lock_count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT MAX(lock_count) FROM {$this->table_name}
                 WHERE ip = %s AND is_blocked = 1",
                $ip
            )
        );
        $lock_count++;

        $lock_duration = ( $lock_count >= $this->settings['max_locks'] )
            ? $this->settings['extended_lock_duration']
            : $this->settings['lock_duration'];

        $blocked_until = date( 'Y-m-d H:i:s', time() + $lock_duration );

        $existing_id = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM {$this->table_name}
                 WHERE ip = %s AND is_blocked = 1
                 ORDER BY id DESC LIMIT 1",
                $ip
            )
        );

        if ( $existing_id ) {
            $wpdb->update(
                $this->table_name,
                array(
                    'blocked_until' => $blocked_until,
                    'lock_count'    => $lock_count,
                    'attempt_time'  => current_time( 'mysql' ),
                ),
                array( 'id' => $existing_id ),
                array( '%s', '%d', '%s' ),
                array( '%d' )
            );
        } else {
            $wpdb->insert(
                $this->table_name,
                array(
                    'ip'            => $ip,
                    'username'      => 'BLOCKED',
                    'attempt_time'  => current_time( 'mysql' ),
                    'blocked_until' => $blocked_until,
                    'lock_count'    => $lock_count,
                    'is_blocked'    => 1,
                ),
                array( '%s', '%s', '%s', '%s', '%d', '%d' )
            );
        }
    }

    private function check_and_auto_ban_ip( $ip ) {
        if ( empty( $this->settings['auto_ban_enabled'] ) ) return;
        if ( $this->is_ip_blacklisted( $ip ) ) return;

        global $wpdb;

        $hours     = (int) $this->settings['auto_ban_window_hours'];
        $threshold = (int) $this->settings['auto_ban_threshold'];

        $count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name}
                 WHERE ip = %s
                 AND attempt_time > DATE_SUB(NOW(), INTERVAL %d HOUR)",
                $ip,
                $hours
            )
        );

        if ( $count >= $threshold ) {
            $blacklist = (array) $this->settings['blacklist'];
            if ( ! in_array( $ip, $blacklist, true ) ) {
                $blacklist[]                 = $ip;
                $this->settings['blacklist'] = $blacklist;
                update_option( $this->settings_option_name, $this->settings );
                // 清除該 IP 的黑名單快取
                wp_cache_delete( 'wu_blacklist_' . md5( $ip ), $this->cache_group );
            }
        }
    }

    public function check_ip_blocked( $user, $username, $password ) {
        if ( empty( $this->settings['enabled'] ) ) return $user;

        $ip = $this->get_client_ip();

        if ( $this->is_ip_blacklisted( $ip ) ) {
            return new WP_Error( 'ip_blacklisted', '您的 IP 位址已被永久阻擋。' );
        }

        if ( $this->is_ip_whitelisted( $ip ) ) return $user;

        if ( $this->is_ip_currently_blocked( $ip ) ) {
            $remaining = $this->get_remaining_block_time( $ip );
            return new WP_Error(
                'ip_blocked',
                sprintf( '您的 IP 位址已被暫時阻擋。請在 %s 後重試。', $this->format_time_remaining( $remaining ) )
            );
        }

        return $user;
    }

    public function clear_failed_attempts( $user_login, $user ) {
        if ( empty( $this->settings['enabled'] ) ) return;

        $ip = $this->get_client_ip();

        global $wpdb;
        $wpdb->delete(
            $this->table_name,
            array( 'ip' => $ip, 'is_blocked' => 0 ),
            array( '%s', '%d' )
        );

        wp_cache_delete( 'wu_blocked_' . md5( $ip ), $this->cache_group );
    }

    public function customize_error_message( $errors ) {
        if ( empty( $this->settings['enabled'] ) ) return $errors;

        $ip = $this->get_client_ip();

        if ( $this->is_ip_currently_blocked( $ip ) ) {
            $remaining = $this->get_remaining_block_time( $ip );
            $errors->add( 'ip_blocked', sprintf(
                '<strong>錯誤</strong>：登入嘗試過於頻繁。請等待 %s 後重試。',
                $this->format_time_remaining( $remaining )
            ) );
        } else {
            $remaining_attempts = $this->get_remaining_attempts( $ip );
            if ( $remaining_attempts > 0 && $remaining_attempts < $this->settings['max_attempts'] ) {
                $errors->add( 'attempts_warning', sprintf(
                    '<strong>警告</strong>：您還有 %d 次嘗試機會。',
                    $remaining_attempts
                ) );
            }
        }

        return $errors;
    }

    public function add_login_page_info() {
        if ( empty( $this->settings['enabled'] ) ) return;

        $ip = $this->get_client_ip();

        if ( $this->is_ip_currently_blocked( $ip ) ) {
            $remaining = $this->get_remaining_block_time( $ip );
            ?>
            <script>
            document.addEventListener('DOMContentLoaded', function() {
                var form = document.getElementById('loginform');
                if (!form) return;
                var el = document.createElement('div');
                el.className = 'message';
                el.style.cssText = 'background:#ffebcd;border-left:4px solid #ff8c00;padding:12px;margin:15px 0;';
                el.innerHTML = '<strong>注意：</strong>您的 IP 已被暫時阻擋。剩餘時間：<?php echo esc_js( $this->format_time_remaining( $remaining ) ); ?>';
                form.parentNode.insertBefore(el, form);
            });
            </script>
            <?php
        } else {
            $remaining_attempts = $this->get_remaining_attempts( $ip );
            if ( $remaining_attempts < $this->settings['max_attempts'] ) {
                ?>
                <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var form = document.getElementById('loginform');
                    if (!form) return;
                    var el = document.createElement('div');
                    el.className = 'message';
                    el.style.cssText = 'background:#fff3cd;border-left:4px solid #ffc107;padding:12px;margin:15px 0;';
                    el.innerHTML = '<strong>提醒：</strong>您還有 <?php echo intval( $remaining_attempts ); ?> 次登入嘗試機會。';
                    form.parentNode.insertBefore(el, form);
                });
                </script>
                <?php
            }
        }
    }

    private function get_client_ip() {
        $proxy_headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
        );

        foreach ( $proxy_headers as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                foreach ( explode( ',', $_SERVER[ $key ] ) as $ip ) {
                    $ip = trim( $ip );
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
                        return $ip;
                    }
                }
            }
        }

        // ✅ REMOTE_ADDR 直接接受（含私有 IP），支援本機/內網環境
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
        return filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '0.0.0.0';
    }

    private function is_ip_whitelisted( $ip ) {
        foreach ( (array) $this->settings['whitelist'] as $range ) {
            if ( $this->ip_in_range( $ip, $range ) ) return true;
        }
        return false;
    }

    // ✅ 加上黑名單快取，TTL 300 秒，減少高流量線性掃描開銷
    private function is_ip_blacklisted( $ip ) {
        $cache_key = 'wu_blacklist_' . md5( $ip );
        $cached    = wp_cache_get( $cache_key, $this->cache_group );
        if ( $cached !== false ) return (bool) $cached;

        $result = false;
        foreach ( (array) $this->settings['blacklist'] as $range ) {
            if ( $this->ip_in_range( $ip, $range ) ) {
                $result = true;
                break;
            }
        }

        wp_cache_set( $cache_key, (int) $result, $this->cache_group, 300 );
        return $result;
    }

    private function ip_in_range( $ip, $range ) {
        $range = trim( $range );
        if ( $range === '' ) return false;

        if ( strpos( $range, '/' ) === false ) {
            return $ip === $range;
        }

        list( $subnet, $mask ) = explode( '/', $range, 2 );
        $mask = (int) $mask;
        if ( $mask < 0 || $mask > 32 ) return false;

        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        if ( $ip_long === false || $subnet_long === false ) return false;

        $mask_long = $mask === 0 ? 0 : ( -1 << ( 32 - $mask ) );
        return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
    }

    // ✅ 加上 wp_cache，TTL 60 秒，減少重複 DB 查詢
    private function is_ip_currently_blocked( $ip ) {
        $cache_key = 'wu_blocked_' . md5( $ip );
        $cached    = wp_cache_get( $cache_key, $this->cache_group );
        if ( $cached !== false ) return (bool) $cached;

        global $wpdb;
        $blocked = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name}
                 WHERE ip = %s AND is_blocked = 1 AND blocked_until > NOW()",
                $ip
            )
        );

        $result = $blocked > 0;
        wp_cache_set( $cache_key, (int) $result, $this->cache_group, 60 );
        return $result;
    }

    private function get_remaining_block_time( $ip ) {
        global $wpdb;

        $blocked_until = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT blocked_until FROM {$this->table_name}
                 WHERE ip = %s AND is_blocked = 1 AND blocked_until > NOW()
                 ORDER BY blocked_until DESC LIMIT 1",
                $ip
            )
        );

        return $blocked_until ? max( 0, strtotime( $blocked_until ) - time() ) : 0;
    }

    private function get_remaining_attempts( $ip ) {
        global $wpdb;

        $recent = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name}
                 WHERE ip = %s AND is_blocked = 0
                 AND attempt_time > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
                $ip,
                self::ATTEMPT_WINDOW_MINUTES
            )
        );

        return max( 0, $this->settings['max_attempts'] - $recent );
    }

    private function format_time_remaining( $seconds ) {
        $seconds = (int) $seconds;
        if ( $seconds <= 0 ) return '0 秒';

        $hours   = floor( $seconds / 3600 );
        $minutes = floor( ( $seconds % 3600 ) / 60 );
        $secs    = $seconds % 60;

        $parts = array();
        if ( $hours )   $parts[] = $hours . ' 小時';
        if ( $minutes ) $parts[] = $minutes . ' 分鐘';
        if ( $secs )    $parts[] = $secs . ' 秒';

        return implode( '', $parts );
    }

    private function get_recent_attempts( $limit = 100 ) {
        global $wpdb;
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->table_name} ORDER BY attempt_time DESC LIMIT %d",
                (int) $limit
            )
        );
    }

    private function get_blocked_ips() {
        global $wpdb;
        return $wpdb->get_results(
            "SELECT ip, MAX(blocked_until) AS blocked_until, MAX(lock_count) AS lock_count
             FROM {$this->table_name}
             WHERE is_blocked = 1 AND blocked_until > NOW()
             GROUP BY ip
             ORDER BY blocked_until DESC"
        );
    }

    private function get_total_attempts() {
        global $wpdb;
        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$this->table_name}" );
    }

    private function get_attempts_in_period( $hours ) {
        global $wpdb;
        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name}
                 WHERE attempt_time > DATE_SUB(NOW(), INTERVAL %d HOUR)",
                (int) $hours
            )
        );
    }

    private function clear_all_logs() {
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wu_login_limiter_settings' ) ) {
            wp_die( '安全驗證失敗' );
        }
        global $wpdb;
        $wpdb->query( "TRUNCATE TABLE {$this->table_name}" );
        echo '<div class="notice notice-success is-dismissible"><p>所有日誌已清除！</p></div>';
    }

    // ✅ 解封：同步清黑名單設定 + 使用原生 SQL 確保 NULL 寫入正確
    private function unblock_ip( $ip ) {
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wu_login_limiter_settings' ) ) {
            wp_die( '安全驗證失敗' );
        }

        // 從黑名單設定移除
        $blacklist = (array) $this->settings['blacklist'];
        $blacklist = array_values( array_filter( $blacklist, function( $b ) use ( $ip ) {
            return trim( $b ) !== $ip;
        } ) );
        $this->settings['blacklist'] = $blacklist;
        update_option( $this->settings_option_name, $this->settings );

        // ✅ 使用直接 SQL 確保 blocked_until 寫入真正的 NULL，而非空字串
        global $wpdb;
        $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$this->table_name}
                 SET is_blocked = 0, blocked_until = NULL
                 WHERE ip = %s",
                $ip
            )
        );

        // 清除快取
        wp_cache_delete( 'wu_blocked_' . md5( $ip ), $this->cache_group );
        wp_cache_delete( 'wu_blacklist_' . md5( $ip ), $this->cache_group );

        echo '<div class="notice notice-success is-dismissible"><p>IP ' . esc_html( $ip ) . ' 已解除阻擋！</p></div>';
    }

    public function schedule_cleanup() {
        if ( ! wp_next_scheduled( 'wu_login_limiter_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wu_login_limiter_cleanup' );
        }
    }

    public function cleanup_old_records() {
        global $wpdb;
        $wpdb->query(
            "DELETE FROM {$this->table_name}
             WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 30 DAY)
             AND (blocked_until IS NULL OR blocked_until < NOW())"
        );
    }
}

new WU_Login_Limiter();
