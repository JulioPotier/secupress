<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
?>
<div><?php _e( 'Security points analysed', 'secupress' ); ?></div>
<a href="<?php echo secupress_admin_url( 'scanners' ) . '&step=2'; ?>">Next Step</a>
<?php
foreach ( $secupress_tests as $module_name => $class_name_parts ) {
	$i = 0;
	?>
	<div class="secupress-table-prio-all<?php echo ( $is_subsite ? '' : ' secupress-table-prio-' . $module_name ); ?>">

		<?php
		if ( ! $is_subsite ) {
			$title   = SecuPress_Settings_Modules::get_module_title( $module_name );
			$summary = SecuPress_Settings_Modules::get_module_summary( $module_name, 'small' );
		?>
		<div class="secupress-prio-title prio-<?php echo $module_name; ?>">
			<?php echo '<' . $heading_tag . ' class="secupress-prio-h" title="' . esc_attr( $summary ) . '">' . $title . ' — ' . $summary . '</' . $heading_tag . '>'; ?>
			<span class="toggle icon-toggle alignright">v^</span>
			<span class="alignright"><a href="<?php echo secupress_admin_url( 'modules', $module_name ); ?>"><?php esc_html_e( 'Go to module\'s settings page', 'secupress' ); ?></a></span>
		</div>

		<?php
		}

		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );

		if ( ! $is_subsite ) {
			foreach ( $class_name_parts as $option_name => $class_name_part ) {
				if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
					unset( $class_name_parts[ $option_name ] );
					continue;
				}

				secupress_require_class( 'scan', $class_name_part );
			}

			// For this priority, order the scans by status: 'good', 'warning', 'good', 'new'.
			$this_prio_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
			$this_prio_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
			$this_prio_good_scans    = array_intersect_key( $class_name_parts, $good_scans );
			$this_new_scans          = array_diff_key( $class_name_parts, $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );
			// $class_name_parts        = array_merge( $this_prio_bad_scans, $this_prio_warning_scans, $class_name_parts, $this_prio_good_scans );
			$class_name_parts        = array_merge( $this_prio_good_scans, $this_prio_warning_scans, $this_prio_bad_scans );
			unset( $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );
		} else {
			foreach ( $class_name_parts as $option_name => $class_name_part ) {
				// Display only scanners where we have a scan result or a fix to be done.
				if ( empty( $scanners[ $option_name ] ) && empty( $fixes[ $option_name ] ) || ! file_exists( secupress_class_path( 'scan', $option_name ) ) ) {
					unset( $class_name_parts[ $option_name ] );
					continue;
				}

				secupress_require_class( 'scan', $class_name_part );
			}
		}
		// Print the rows.
		foreach ( $class_name_parts as $option_name => $class_name_part ) {
			++$i;
			$class_name   = 'SecuPress_Scan_' . $class_name_part;
			$current_test = $class_name::get_instance();
			$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners' . ( $is_subsite ? '' : '#' . $class_name_part ) ) ) );
			$is_fixable   = true === $current_test::$fixable || 'pro' === $current_test::$fixable && secupress_is_pro();

			// Scan.
			$scanner        = isset( $scanners[ $option_name ] ) ? $scanners[ $option_name ] : array();
			$scan_status    = ! empty( $scanner['status'] ) ? $scanner['status'] : 'notscannedyet';
			$scan_nonce_url = 'secupress_scanner_' . $class_name_part . ( $is_subsite ? '-' . $site_id : '' );
			$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) ), $scan_nonce_url );
			$scan_message   = '&#175;';

			if ( ! empty( $scanner['msgs'] ) ) {
				$scan_message = '<span class="secupress-scan-result-label">' . _x( 'Scan result: ', 'noun', 'secupress' ) . '</span> ' . secupress_format_message( $scanner['msgs'], $class_name_part );
			}

			// Fix.
			$fix             = ! empty( $fixes[ $option_name ] ) ? $fixes[ $option_name ] : array();
			$fix_status_text = ! empty( $fix['status'] ) && 'good' !== $fix['status'] ? secupress_status( $fix['status'] ) : '';
			$fix_nonce_url   = 'secupress_fixit_' . $class_name_part . ( $is_subsite ? '-' . $site_id : '' );
			$fix_nonce_url   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) ), $fix_nonce_url );
			$fix_message     = '';

			if ( ! empty( $fix['msgs'] ) && 'good' !== $scan_status ) {
				$scan_message = '<span class="secupress-fix-result-label">' . _x( 'Fix result: ', 'noun', 'secupress' ) . '</span> ' . secupress_format_message( $fix['msgs'], $class_name_part );
			}

			// Row css class.
			$row_css_class  = ' type-' . sanitize_key( $class_name::$type );
			$row_css_class .= ' status-' . sanitize_html_class( $scan_status );
			$row_css_class .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
			$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
			$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
			$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';

			if ( $is_subsite ) {
				$row_css_class .= 0 === $i % 2 ? '' : ' alternate';
			} else {
				$row_css_class .= 0 === $i % 2 ? ' alternate-2' : ' alternate-1';
			}
			?>
			<div id="<?php echo $class_name_part; ?>" class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all<?php echo $row_css_class; ?>">

				<div class="secupress-flex secupress-flex-top secupress-flex-spaced">
					<div class="secupress-item-header">
						<p class="secupress-item-title"><?php echo $class_name::$title; ?></p>

						<div class="secupress-row-actions">
							<span class="hide-if-no-js">
								<button type="button" class="secupress-details link-like" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get details', 'secupress' ); ?>">
									<span class="icon" aria-hidden="true">
										<i class="icon-info-disk"></i>
									</span>
									<span class="text">
										<?php _e( 'Learn more', 'secupress' ); ?>
									</span>
								</button>
							</span>
						</div>
					</div><!-- .secupress-item-header -->

					<div class="secupress-item-actions-fix">
						<div class="secupress-fix-status-text"><?php echo $fix_status_text; ?></div>

						<div class="secupress-fix-status-actions">
							<?php
							if ( $is_fixable ) {
								// It can be fixed.
								?>
								<a class="secupress-button-primary secupress-button-mini secupress-fixit<?php echo $current_test::$delayed_fix ? ' delayed-fix' : ''; ?>" href="<?php echo esc_url( $fix_nonce_url ); ?>">
									<span class="icon" aria-hidden="true">
										<i class="icon-shield"></i>
									</span>
									<span class="text">
										<?php _e( 'Fix it', 'secupress' ); ?>
									</span>
								</a>
								<div class="secupress-row-actions">
									<button type="button" class="secupress-details-fix link-like hide-if-no-js" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get fix details', 'secupress' ); ?>">
										<?php _e( 'How?', 'secupress' ); ?>
									</button>
								</div>
								<?php
							} elseif ( 'pro' === $current_test::$fixable ) { // //// #.
								// It is fixable with the pro version but the free version is used.
								?>
								<button type="button" class="secupress-button-primary secupress-button-mini secupress-go-pro">
									<?php esc_html_e( 'Fix it with Pro', 'secupress' ); ?>
									<i class="icon-secupress-simple" aria-hidden="true"></i>
								</button>
								<?php
							} else {
								// Really not fixable by the plugin, the user must di it manually.
								?>
								<em class="secupress-gray">
									<?php esc_html_e( 'Cannot be fixed automatically.', 'secupress' ); ?>
								</em>
								<button type="button" class="secupress-details-fix secupress-button secupress-button-mini secupress-button-primary secupress-button-ghost hide-if-no-js" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get fix details', 'secupress' ); ?>">
									<span class="icon" aria-hidden="true">
										<i class="icon-shield"></i>
									</span>
									<span class="text">
										<?php _e( 'How to fix?', 'secupress' ); ?>
									</span>
								</button>
								<?php
							}
							?>
						</div><!-- .secupress-fix-status-actions -->
					</div>
				</div><!-- .secupress-flex -->

				<div class="secupress-flex secupress-flex-spaced secupress-scan-result-n-actions">
					<div class="secupress-scan-result">
						<div class="secupress-scan-message">
							<?php echo $scan_message; ?>
						</div>
					</div>

					<div class="secupress-scan-actions">
						<p>
							<a class="secupress-button secupress-button-mini secupress-scanit" href="<?php echo esc_url( $scan_nonce_url ); ?>">
								<span class="icon" aria-hidden="true">
									<i class="icon-refresh"></i>
								</span>
								<span class="text">
									<?php echo 'notscannedyet' === $scan_status ? _x( 'Scan', 'verb', 'secupress' ) : _x( 'Re-Scan', 'verb', 'secupress' ); ?>
								</span>
							</a>
						</p>
					</div>
				</div>

				<?php if ( $is_fixable ) :
					$support_href = secupress_is_pro() ? 'http://secupress.me/support/?item=' . $option_name : 'https://wordpress.org/support/plugin/secupress-free#postform'; // Correct slug on repo? ////.
					?>
					<div class="secupress-fix-result-actions secupress-bg-gray">
						<div class="secupress-flex secupress-flex-spaced secupress-fix-result">
							<div class="secupress-fix-result-message"><?php echo $fix_message; ?></div>

							<?php
							if ( $is_fixable ) {
								// We didn't display the "Fix it" button earlier, we display this one instead.
								?>
								<div class="secupress-fix-result-retryfix">
									<a href="<?php echo esc_url( $fix_nonce_url ); ?>" class="secupress-button secupress-button-primary secupress-button-mini secupress-retry-fixit">
										<span class="icon" aria-hidden="true">
											<i class="icon-shield"></i>
										</span>
										<span class="text">
											<?php esc_html_e( 'Retry to fix', 'secupress' ); ?>
										</span>
									</a>
									<div class="secupress-row-actions">
										<button type="button" class="secupress-details-fix link-like hide-if-no-js" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get fix details', 'secupress' ); ?>">
											<?php _e( 'How?', 'secupress' ); ?>
										</button>
									</div>
								</div>
								<?php
							}
							?>
						</div>

						<p>
							<a href="<?php echo $class_name::DOC_URL; ?>" class="secupress-button secupress-button-mini">
								<span class="icon" aria-hidden="true">
									<i class="icon-file-text"></i>
								</span>
								<span class="text">
									<?php esc_html_e( 'Read the documentation', 'secupress' ); ?>
								</span>
							</a>
							<a href="<?php echo $support_href; ?>" class="secupress-button secupress-button-mini secupress-ask-support secupress-ask-support-<?php echo secupress_is_pro() ? 'pro' : 'free'; ?>">
								<span class="icon" aria-hidden="true">
									<i class="icon-ask"></i>
								</span>
								<span class="text">
									<?php esc_html_e( 'Ask support about it', 'secupress' ); ?>
								</span>
							</a>
						</p>
					</div>
				<?php endif; ?>

				<?php // Hidden items used for Sweet Alerts. ?>
				<div id="details-<?php echo $class_name_part; ?>" class="details hide-if-js">
					<?php _e( 'Scan Details: ', 'secupress' ); ?>
					<span class="details-content"><?php echo wp_kses( $current_test::$more, $allowed_tags ); ?></span>
				</div>

				<div id="details-fix-<?php echo $class_name_part; ?>" class="details hide-if-js">
					<?php _e( 'Fix Details: ', 'secupress' ); ?>
					<span class="details-content"><?php echo wp_kses( $current_test::$more_fix, $allowed_tags ); ?></span>
				</div>

			</div><!-- .secupress-item-all -->

			<?php
			if ( $class_name_part === $fix_actions[0] ) {
				$fix_actions = explode( ',', $fix_actions[1] );
				$fix_actions = array_combine( $fix_actions, $fix_actions );
				$fix_actions = $current_test->get_required_fix_action_template_parts( $fix_actions );

				if ( $fix_actions ) { ?>
					<div class="test-fix-action">
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<h3><?php echo _n( 'This action requires your attention', 'These actions require your attention', count( $fix_actions ), 'secupress' ); ?></h3>
							<?php
							echo implode( '', $fix_actions );
							echo '<p class="submit"><button type="submit" name="submit" class="secupress-button secupress-button-primary">' . __( 'Fix it', 'secupress' ) . "</button></p>\n";
							$current_test->for_current_site( $is_subsite )->get_fix_action_fields( array_keys( $fix_actions ) );
							?>
						</form>
					</div>
					<?php
				}

				$fix_actions = array( 0 => false );
			}
		}
		?>

	</div>
	<?php
} // foreach modules
