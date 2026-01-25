<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Register the correct setting with the correct callback for the module.
 *
 * @param (string) $module      A module. Used to build the option group and maybe the option name.
 * @param (string) $option_name An option name.
 *
 * @since 1.0
 */
function secupress_register_setting( $module, $option_name = false ) {
	$option_group      = "secupress_{$module}_settings";
	$option_name       = $option_name ? $option_name : "secupress_{$module}_settings";
	$sanitize_module   = str_replace( '-', '_', $module );
	$sanitize_callback = "secupress_pro_{$sanitize_module}_settings_callback";

	if ( ! secupress_is_pro() || ! function_exists( $sanitize_callback ) ) {
		$sanitize_callback = "secupress_{$sanitize_module}_settings_callback";
	}

	if ( ! is_multisite() ) {
		if ( is_admin() ) {
			// Filter the capability required when using the Settings API.
			add_filter( "option_page_capability_$option_group", 'secupress_setting_capability_filter' );
		}
		// Register the setting.
		register_setting( $option_group, $option_name, $sanitize_callback );
		return;
	}

	$whitelist = secupress_cache_data( 'new_whitelist_network_options' );
	$whitelist = is_array( $whitelist ) ? $whitelist : [];
	$whitelist[ $option_group ]   = isset( $whitelist[ $option_group ] ) ? $whitelist[ $option_group ] : array();
	$whitelist[ $option_group ][] = $option_name;
	secupress_cache_data( 'new_whitelist_network_options', $whitelist );

	add_filter( "sanitize_option_{$option_name}", $sanitize_callback );
}


/**
 * Used to filter the capability required when using the Settings API.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_setting_capability_filter() {
	return secupress_get_capability();
}

/**
 * Print the scanner UI.
 * 
 * @since 1.0
 * @author Julio Potier
 *
 * @param (array) $scanner_results An array of scanner results.
 */
function secupress_print_scanner_ui( $scanner_results = [] ) {
	global $wpdb, $running, $scan_ko, $last_scan;
	
	$scanners   = secupress_get_malware_scanners();
	$last_scan  = secupress_get_malware_scan_last_time();
	$has_warning = false;

	if ( secupress_is_pro() && function_exists( 'secupress_file_monitoring_get_instance' ) ) {
		$running = secupress_file_monitoring_get_instance()->is_monitoring_running();
	} else {
		$running = false;
	}

	$signature_scanners           = 0;
	$signature_scanners_with_file = 0;
	foreach ( $scanners as $scanner ) {
		$scanner_file  = isset( $scanner['file'] ) ? $scanner['file'] : null;
		$scanner_class = isset( $scanner['class'] ) ? $scanner['class'] : '';
		$is_under_dev  = false !== stripos( $scanner_class, 'unavailable' );

		if ( $scanner_file && is_string( $scanner_file ) && ! $is_under_dev ) {
			$signature_scanners++;
			$filename = secupress_get_data_file_path( $scanner_file );
			if ( $filename && file_exists( $filename ) ) {
				$signature_scanners_with_file++;
			}
		}
	}

	$all_signature_files_missing = $signature_scanners > 0 && 0 === $signature_scanners_with_file;
	$scan_ko                     = $all_signature_files_missing ? 1 : 0;

	$promo_classes = 'secupress-scanner-promo';
	if ( $running ) {
		$promo_classes .= ' secupress-scanner-promo-running';
	}
	?>
	<div class="<?php echo esc_attr( $promo_classes ); ?>">
		<div class="secupress-scanner-promo-header">
			<img src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>icon-radar.png" alt="" class="secupress-scanner-promo-img">
			<div>
				<h4><?php _e( 'Deep Malware Scanning', 'secupress' ); ?></h4>
				<p><?php _e( 'Scan your entire WordPress installation for malware, backdoors, and suspicious code.', 'secupress' ); ?></p>
			</div>
		</div>
		<p class="secupress-scanner-last-scan">
			<?php
			if ( $last_scan ) {
				$date_format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
				$date_text   = human_time_diff( $last_scan );
				$abbr_text   = date_i18n( $date_format, $last_scan );
				printf( esc_html__( 'Last scan: %s ago', 'secupress' ), sprintf( '<abbr title="%s">%s</abbr>', esc_attr( $abbr_text ), secupress_tag_me( esc_html( $date_text ), 'strong' ) ) );
			} else {
				_e( 'No scan has been run yet.', 'secupress' );
			}
			?>
		</p>
		
		<div class="secupress-scanner-features">
		<?php
		foreach ( $scanners as $scanner ) { 
			$scanner_file    = isset( $scanner['file'] )  ? $scanner['file']  : null;
			$scanner_cback   = isset( $scanner['cback'] ) ? $scanner['cback'] : null;
			$scanner_class   = isset( $scanner['class'] ) ? $scanner['class'] : '';
			$is_under_dev    = false !== stripos( $scanner_class, 'unavailable' );
			$is_core_scanner = isset( $scanner['icon'] ) && 'core' === $scanner['icon'];

			$file_available = true;
			if ( ! $is_under_dev && $scanner_file && is_string( $scanner_file ) ) {
				$filename       = secupress_get_data_file_path( $scanner_file );
				$file_available = $filename && file_exists( $filename );
			}

			$results_key = null;
			if ( is_string( $scanner_file ) ) {
				$results_key = $scanner_file;
			} elseif ( $is_core_scanner ) {
				$results_key = 'core-integrity';
			}

			$has_html_results = $results_key && isset( $scanner_results[ $results_key ]['html'] ) && ! empty( trim( $scanner_results[ $results_key ]['html'] ) );

			$cback_ran        = false;
			$cback_has_data   = false;

			if ( ! $is_under_dev && $file_available && $scanner_cback && is_callable( $scanner_cback ) ) {
				$cback_result   = call_user_func( $scanner_cback );
				$cback_ran      = true;
				$cback_has_data = ! empty( array_filter( $cback_result ) );
			}

			if ( $all_signature_files_missing ) {
				$state       = 'file-missing';
				$status_text = secupress_is_pro() ? __( 'Unavailable, signature file missing', 'secupress' ) : __( 'Pro version required to continue', 'secupress' );
				$state_class = 'state-file-missing';
			} elseif ( $is_under_dev ) {
				$state       = 'dev';
				$status_text = __( 'Under development', 'secupress' );
				$state_class = 'state-dev';
			} elseif ( $scanner_file && ! $file_available ) {
				$state       = 'file-missing';
				$status_text = secupress_is_pro() ? __( 'Unavailable, signature file missing', 'secupress' ) : __( 'Pro version required to continue', 'secupress' );
				$state_class = 'state-file-missing';
			} elseif ( $cback_ran && ! $is_core_scanner ) {
				if ( $cback_has_data ) {
					if ( $results_key && isset( $scanner_results[ $results_key ]['html'] ) ) {
						if ( empty( trim( $scanner_results[ $results_key ]['html'] ) ) ) {
							$state       = 'clean';
							$status_text = __( 'Scanned, nothing found', 'secupress' );
							$state_class = 'state-available';
						} else {
							if ( empty( $scanner_results[ $results_key ]['count'] ) ) {
								$state       = 'clean';
								$status_text = __( 'Scanned, nothing found', 'secupress' );
								$state_class = 'state-available';
							} else {
								$state       = 'warning';
								$status_text = sprintf( _n( 'Scanned, %d issue found', 'Scanned, %d issues found', $scanner_results[ $results_key ]['count'], 'secupress' ), $scanner_results[ $results_key ]['count'] );
								$state_class = 'state-warning';
							}
						}
					}
				} elseif ( $last_scan ) {
					$state       = 'clean';
					$status_text = __( 'Scanned, nothing found', 'secupress' );
					$state_class = 'state-available';
				} else {
					$state       = 'not-scanned';
					$status_text = __( 'Not scanned yet', 'secupress' );
					$state_class = 'state-available';
				}
			} elseif ( $has_html_results ) {
				if ( empty( $scanner_results[ $results_key ]['count'] ) ) {
					$state       = 'clean';
					$status_text = __( 'Scanned, nothing found', 'secupress' );
					$state_class = 'state-available';
				} else {
					$state       = 'warning';
					$status_text = sprintf( _n( 'Scanned, %d issue found', 'Scanned, %d issues found', $scanner_results[ $results_key ]['count'], 'secupress' ), $scanner_results[ $results_key ]['count'] );
					$state_class = 'state-warning';
				}
			} elseif ( $last_scan ) {
				$state       = 'clean';
				$status_text = __( 'Scanned, nothing found', 'secupress' );
				$state_class = 'state-available';
			} else {
				$state       = 'not-scanned';
				$status_text = __( 'Not scanned yet', 'secupress' );
				$state_class = 'state-available';
			}

			if ( 'warning' === $state ) {
				$has_warning = true;
			}

			if ( $running && 'dev' !== $state && 'file-missing' !== $state ) {
				$state       = 'scanning';
				$status_text = __( 'Scanning…', 'secupress' );
				$state_class = 'state-available';
			}

			$scanner_id  = $results_key ? sanitize_html_class( $results_key ) : sanitize_title( $scanner['name'] );
			$show_toggle = secupress_is_pro() && ! $running && 'dev' !== $state;
		?>
		<div class="secupress-scanner-feature <?php echo esc_attr( $state_class ); ?>">
			<?php if ( $running && 'dev' !== $state && 'file-missing' !== $state ) { ?>
				<span class="spinner secupress-inline-spinner secupress-inline-spinner-active"></span>
			<?php } else { ?>
				<span class="secupress-icon secupress-icon-<?php echo esc_attr( $scanner['icon'] ); ?>"></span>
			<?php } ?>
			<div class="secupress-scanner-feature-content">
				<div class="secupress-scanner-feature-header">
					<strong><?php echo esc_html( $scanner['name'] ); ?></strong>
					<span class="secupress-scanner-feature-desc"><?php echo esc_html( $scanner['desc'] ); ?></span>
				</div>
				<div class="secupress-scanner-feature-status">
					<span class="secupress-scanner-status-text"><?php echo esc_html( $status_text ); ?></span>
					<?php if ( $show_toggle ) { ?>
						<button type="button" class="secupress-scanner-toggle-btn" data-target="secupress-results-<?php echo $scanner_id; ?>" aria-expanded="false" title="<?php esc_attr_e( 'View details', 'secupress' ); ?>">
							<span class="dashicons dashicons-arrow-down-alt2"></span>
						</button>
					<?php } ?>
				</div>
			</div>
		</div>
		<?php if ( $show_toggle ) { ?>
			<div id="secupress-results-<?php echo $scanner_id; ?>" class="secupress-scanner-results-content" style="display: none;">
				<?php 
				if ( $results_key && isset( $scanner_results[ $results_key ]['html'] ) ) {
					$content = trim( $scanner_results[ $results_key ]['html'] );
					if ( ! empty( $content ) ) {
						echo $scanner_results[ $results_key ]['html'];
					} elseif ( 'warning' === $state ) {
						echo '<p class="secupress-scanner-info-message"><span class="dashicons dashicons-info"></span> ' . esc_html__( 'All detected links have already been added to the allowed list. No action needed.', 'secupress' ) . '</p>';
					}
				} elseif ( 'file-missing' === $state ) {
					echo '<p class="secupress-scanner-info-message"><span class="dashicons dashicons-warning"></span> ' . esc_html__( 'The signature file for this scanner is missing. Wait 12 hours, or update the data, or contact our support team.', 'secupress' ) . '</p>';
				} elseif ( 'clean' === $state ) {
					echo '<p class="secupress-scanner-info-message secupress-scanner-info-success"><span class="dashicons dashicons-yes-alt"></span> ' . esc_html__( 'Last scan completed successfully. No issues found.', 'secupress' ) . '</p>';
				} elseif ( 'not-scanned' === $state ) {
					echo '<p class="secupress-scanner-info-message"><span class="dashicons dashicons-info"></span> ' . esc_html__( 'This scanner has not been run yet. "Run Scan" to start.', 'secupress' ) . '</p>';
				}
				?>
			</div>
		<?php } ?>
		<?php } ?>
		</div>

		<?php
		if ( ! secupress_is_pro() ) {
		?>
		<div class="secupress-scanner-cta-alert free">
			<div class="secupress-scanner-blocked">
				<div class="secupress-scanner-progress">
					<div class="secupress-scanner-fill"></div>
					<div class="secupress-scanner-blocker">
						<span class="dashicons dashicons-lock"></span>
					</div>
					<span class="secupress-scanner-status"><?php _e( 'Get <strong>Pro version</strong> to continue', 'secupress' ); ?></span>
				</div>
			</div>
			<div class="secupress-scanner-cta">
				<span class="secupress-button light disabled" data-cta-title="<?php echo esc_attr__( 'Malware Scanner', 'secupress' ); ?>">
					<?php _e( 'Run Scan', 'secupress' ); ?>
					<span class="dashicons dashicons-arrow-right-alt2"></span>
				</span>
			</div>
		</div>
		<?php
		} else {
			if ( ! empty( $scan_ko ) ) {
				$label      = __( 'Unavailable', 'secupress' );
				$info       = __( 'Scanners unavailable right now', 'secupress' );
				$bar_class  = ' disabled" disabled="disabled"';
				$btn_class  = ' disabled';
				$turn       = 'none';
				$url        = '#';
				$icon       = 'dashicons dashicons-warning';
				$icon_btn   = 'dashicons dashicons-warning';
			} elseif ( $running ) {
				$label      = __( 'Stop Scan', 'secupress' );
				$bar_class  = ' working';
				$btn_class  = ' secupress-button-secondary';
				$turn       = 'off';
				$icon       = '';
				$icon_btn   = 'dashicons dashicons-dismiss';
				$url        = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_toggle_file_scan&turn=' . $turn ), 'secupress_toggle_file_scan' ) );
			} else {
				$label      = __( 'Run Scan', 'secupress' );
				$info       = __( 'Scanner ready', 'secupress' );
				$bar_class  = '';
				$btn_class  = ' secupress-button-primary';
				$turn       = 'on';
				$icon       = 'dashicons dashicons-yes-alt';
				$icon_btn   = 'dashicons dashicons-update';
				$url        = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_toggle_file_scan&turn=' . $turn ), 'secupress_toggle_file_scan' ) );
			}

			?>
			<div class="secupress-scanner-cta-alert pro">
				<div class="secupress-scanner-blocked">
					<div class="secupress-scanner-progress <?php echo $bar_class; ?>">
						<div class="secupress-scanner-fill"></div>
						<?php if ( ! $running && empty( $scan_ko ) ) { ?>
							<div class="secupress-scanner-blocker">
								<span class="<?php echo $icon; ?>"></span>
							</div>
							<span class="secupress-scanner-status"><?php echo esc_html( $info ); ?></span>
						<?php } elseif ( ! empty( $scan_ko ) ) { ?>
							<div class="secupress-scanner-blocker">
								<span class="dashicons dashicons-warning"></span>
							</div>
							<span class="secupress-scanner-status"><?php _e( 'Scanners unavailable right now', 'secupress' ); ?></span>
						<?php } ?>
					</div>
				</div>
				<div class="secupress-scanner-cta">
					<a data-original-i18n="<?php esc_attr_e( 'Run Scan', 'secupress' ); ?>" data-loading-i18n="<?php esc_attr_e( 'Loading&hellip;', 'secupress' ); ?>" id="toggle_file_scanner" href="<?php echo $url; ?>" class="secupress-button <?php echo sanitize_html_class( $btn_class ); ?>">
						<?php echo esc_html( $label ); ?>
						<span class="secupress-icon <?php echo $icon_btn; ?>"></span>
					</a>
				</div>
				<?php
				$label_scan    = '';
				$full_filetree = secupress_get_site_transient( SECUPRESS_FULL_FILETREE );
				$label_scan    = 'off' === $turn ? '<p><code>' . __( 'Cleaning', 'secupress' ) . '&hellip;</code></p>' : '';
				if ( $running && is_array( $full_filetree ) ) {
					$label_scan     = __( 'Scanning: %s', 'secupress' );
					if ( ! isset( $full_filetree[1] ) && ABSPATH === $full_filetree[0] ) {
						$label_scan = sprintf( $label_scan, '<code>' . esc_html( sprintf( __( 'Database: %s', 'secupress' ), $wpdb->posts . ', ' . $wpdb->options . '&hellip;' ) ) . '</code>' );
					} else {
						$label_scan = sprintf( $label_scan, '<code>' . esc_html( __( 'Loading paths', 'secupress' ) ) . '&hellip;</code>' );
					}
					$label_scan    .= ' <span class="secupress-icon secupress-icon-loader"></span>';
				}

				if ( $running ) {
				?>
					<p class="secupress-scanner-info-wrapper">
						<span id="secupress-scanner-info" data-nonce="<?php echo wp_create_nonce( 'secupress_malwareScanStatus' ); ?>">
							<?php echo $label_scan; ?>
						</span>
					</p>
				<?php 
				}
				?>
			</div>
			<?php
		}

		if ( $has_warning && ! $running ) {
			?>
			<div class="secupress-help-banner">
				<div class="secupress-help-banner-content">
					<div class="secupress-help-banner-icon">
						<span class="dashicons dashicons-sos"></span>
					</div>
					<div class="secupress-help-banner-text">
						<p class="secupress-help-banner-title"><?php _e( 'What to do now?', 'secupress' ); ?></p>
						<p><?php _e( 'Check each file content using FTP and each post content to determine if it has to be cleaned, deleted or is a false positive.', 'secupress' ); ?></p>
						<p class="secupress-help-banner-highlight"><?php _e( 'Need help cleaning your hacked website? Our security experts are here for you!', 'secupress' ); ?></p>
					</div>
					<div class="secupress-help-banner-cta">
						<a class="secupress-button secupress-button-tertiary" href="<?php echo esc_url( secupress_admin_url( 'get-pro' ) ); ?>#services">
							<span class="dashicons dashicons-businessman"></span>
							<?php _e( 'Ask an Expert', 'secupress' ); ?>
						</a>
					</div>
				</div>
			</div>
			<?php
		}
		?>
	</div>
	<?php
}
