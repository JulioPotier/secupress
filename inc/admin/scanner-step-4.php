<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$modules                = secupress_get_modules();
?>

	<div id="secupress-tests" class="secupress-tests secupress-is-finish-report secupress-box-shadow">

		<div class="secupress-summary-header secupress-section-dark">
			<div class="secupress-flex">
				<div class="secupress-col-logo">
					<?php echo secupress_get_logo( array( 'width' => 81 ) ); ?>
				</div>
				<div class="secupress-col-summary-text">
					<p class="secupress-text-medium secupress-mb0"><?php printf( __( 'Congratulations! You fixed %1$d of %2$d.', 'secupress' ), 25, 30 ); ?></p>
					<p><?php printf( __( 'Your grade went from %1$s to %2$s. You fixed:', 'secupress' ), 'D', 'B' ); ?></p>

					<div class="secupress-flex secupress-flex-spaced">
						<div>
							<ul class="secupress-chart-legend">
								<li class="status-bad">
									<span class="secupress-carret"></span>
									<?php printf( esc_html__( '%d Bad', 'secupress' ), 20 ); ?>
									<span class="secupress-count-bad"></span>
								</li>
								<li class="status-warning">
									<span class="secupress-carret"></span>
									<?php printf( esc_html__( '%d Warning', 'secupress' ), 3 ); ?>
									<span class="secupress-count-warning"></span>
								</li>
							</ul>
						</div>
						<p>
							<button class="secupress-button secupress-button-ghost secupress-button-mini hide-is-no-js" type="button" data-target="secupress-summaries" data-trigger="slidetoggle" title="<?php esc_attr_e('Show/hide the details of scanned items in your report', 'secupress' ); ?>">
								<span class="icon">
									<i class="icon-angle-down" aria-hidden="true"></i>
								</span>
								<span class="text" aria-hidden="true">
									<span class="hidden-when-activated">
										<?php esc_html_e( 'Show the list items', 'secupress' ); ?>
									</span>
									<span class="visible-when-activated">
										<?php esc_html_e( 'Hide the list items', 'secupress' ); ?>
									</span>
								</span>
							</button>
						</p>
					</div>
				</div>
			</div>
		</div><!-- .secupress-summary-header -->

		<div id="secupress-summaries" class="secupress-summaries hide-if-js">

<?php
//// new items not working yet.
foreach ( $secupress_tests as $module_name => $class_name_parts ) {
	$i = 0;

	$module_title     = ! empty( $modules[ $module_name ]['title'] )              ? $modules[ $module_name ]['title']              : '';
	$module_summary   = ! empty( $modules[ $module_name ]['summaries']['small'] ) ? $modules[ $module_name ]['summaries']['small'] : '';
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

	?>
		<div class="secupress-scans-group secupress-group-<?php echo $module_name; ?>">

		<?php
		if ( ! $is_subsite ) {
		?>
			<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

				<div class="secupress-sgh-name">
					<i class="icon-user-login" aria-hidden="true"></i>
					<p class="secupress-sgh-title"><?php echo $module_title; ?></p>
					<p class="secupress-sgh-description"><?php echo $module_summary; ?></p>
				</div>

				<div class="secupress-sgh-actions secupress-flex">
					<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-<?php echo $module_name; ?>">
						<i class="icon-angle-up" aria-hidden="true"></i>
						<span class="screen-reader-text"><?php _e( 'Show/hide panel', 'secupress' ); ?></span>
					</button>
				</div>

			</div><!-- .secupress-sg-header -->

			<div id="secupress-group-content-<?php echo $module_name; ?>" class="secupress-sg-content">
		<?php
		}

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
				$scan_message = secupress_format_message( $scanner['msgs'], $class_name_part );
			}

			// Fix.
			$fix             = ! empty( $fixes[ $option_name ] ) ? $fixes[ $option_name ] : array();
			$fix_status_text = ! empty( $fix['status'] ) && 'good' !== $fix['status'] ? secupress_status( $fix['status'] ) : '';
			$fix_nonce_url   = 'secupress_fixit_' . $class_name_part . ( $is_subsite ? '-' . $site_id : '' );
			$fix_nonce_url   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) ), $fix_nonce_url );
			$fix_message     = '';

			if ( ! empty( $fix['msgs'] ) && 'good' !== $scan_status ) {
				$scan_message = secupress_format_message( $fix['msgs'], $class_name_part );
			}

			// Row css class.
			$row_css_class  = ' type-' . sanitize_key( $class_name::$type );
			$row_css_class .= ' status-' . sanitize_html_class( $scan_status );
			$row_css_class .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
			$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
			$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
			$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';

			switch( $scan_status ) {
				
				case 'bad' :
					$icon_slug = 'cross-o';
					$scan_status_word = esc_html__( 'Not Fixed', 'secupress' );
					break;

				case 'warning' :
					$icon_slug = 'exclamation-o';
					$scan_status_word = esc_html__( 'Error', 'secupress' );
					break;

				case 'pending' :
					$icon_slug = 'clock-o-2';
					$scan_status_word = esc_html__( 'Pending', 'secupress' );
					break;

				default :
					$icon_slug = 'check';
					$scan_status_word = esc_html__( 'Fixed', 'secupress' );
			}

			?>

				<div class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all <?php echo $row_css_class; ?>" id="<?php echo $class_name_part; ?>">

					<div class="secupress-flex">

						<p class="secupress-item-status secupress-status-mini">
							<span class="secupress-dot-<?php echo $scan_status; ?>"></span>
						</p>

						<p class="secupress-item-title"><?php echo $scan_message; ?></p>

						<p class="secupress-row-actions">
							<span class="secupress-status secupress-status-<?php echo sanitize_html_class( $scan_status ); ?>">
								<i class="icon-<?php echo $icon_slug; ?>" aria-hidden="true"></i>
								<?php echo $scan_status_word; ?></span>
						</p>
					</div><!-- .secupress-flex -->
				</div><!-- .secupress-item-all -->

			<?php
		}
		?>

			</div><!-- .secupress-sg-content -->
		</div><!-- .secupress-scans-group -->

	<?php
}
?>
		<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced">
			<?php
				$export_pdf_btn = '<span class="icon">
						<i class="icon-file-pdf-o" aria-hidden="true"></i>
					</span>
					<span class="text">
						' . esc_html__( 'Export as PDF', 'secupress' ) . '
					</span>';
			?>
			<p>
			<?php
				if ( ! secupress_is_pro() ) {
			?>
				<button type="button" title="<?php esc_attr__( 'Export this report as PDF file.', 'secupress' ); ?>" class="secupress-button shadow">
					<?php echo $export_pdf_btn; ?>
				</button>
			<?php
				} else {
			?>
				<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ) ?>" type="button" title="<?php echo $get_pdf_title; ?>" target="_blank" class="secupress-button disabled shadow">
					<?php echo $export_pdf_btn; ?>
				</a>
				<br>
				<span class="secupress-get-pro-version">
					<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
				</span>
			<?php
				}
			?>
			</p>
		</div><!-- .secupress-step-content-footer -->
	</div><!-- .secupress-summaries -->

	<div class="secupress-go-farther">
		<div class="secupress-flex">
			<div class="secupress-col">
				<p class="secupress-farther-title"><?php _e( 'Want to go farther?', 'secupress' ); ?></p>
				<p class="secupress-farther-desc"><?php _e( 'Rendezvous on the modules pages to discover our features and improve your security even more.', 'secupress' ); ?></p>
			</div>
			<div class="secupress-col secupress-col-action">
				<a href="#secupress-latest" class="secupress-rich-link secupress-current">
					<span class="secupress-label-with-icon">
						<i aria-hidden="true" class="icon-cogs rounded"></i>
						<span class="secupress-upper"><?php printf( esc_html__( '%s modules', 'secupress' ), SECUPRESS_PLUGIN_NAME ); ?></span>
						<span class="secupress-description"><?php _e( 'Fine tuning for your WordPress', 'secupress' ); ?></span>
					</span>
				</a>
			</div>
		</div>
		<div class="secupress-flex">
			<div class="secupress-col">
				<p class="secupress-farther-title"><?php _e( 'Schedule your next scans', 'secupress' ); ?></p>
				<p class="secupress-farther-desc"><?php _e( 'Keep up the good security by scheduling your next scans. No need to do it manually each week anymore…', 'secupress' ); ?></p>
			</div>
			<div class="secupress-col secupress-col-action">
				<a href="#secupress-latest" class="secupress-rich-link secupress-current">
					<span class="secupress-label-with-icon">
						<i aria-hidden="true" class="icon-calendar rounded"></i>
						<span class="secupress-upper"><?php esc_html_e( 'Schedule Scans', 'secupress' ); ?></span>
						<span class="secupress-description"><?php _e( 'Program recurring scans', 'secupress' ); ?></span>
					</span>
				</a>
			</div>
		</div>
	</div><!-- .secupress-go-farther -->

</div><!-- .secupress-tests -->


<?php if ( ! secupress_is_pro() ) { ?>
<div class="secupress-pro-summary secupress-box-shadow">
	<div class="secupress-summary-header secupress-section-dark">
		<div class="secupress-flex">
			<div class="secupress-col-logo">
				<?php echo secupress_get_logo( array( 'width' => 81 ), true ); ?>
			</div>
			<div class="secupress-col-summary-text secupress-flex secupress-flex-spaced">
				<p class="secupress-text-medium secupress-mb0"><?php _e( 'Perform a better grade<br> and unlock these awesome features', 'secupress' ); ?></p>

				
				<p class="secupress-p1">
					<a href="#" class="secupress-button secupress-button-tertiary secupress-button-getpro">
						<span class="icon">
							<i class="icon-secupress-simple" aria-hidden="true"></i>
						</span>
						<span class="text">
							<?php esc_html_e( 'Get Pro', 'secupress' ); ?>	
						</span>
					</a>
				</p>
			</div>
		</div>
	</div><!-- .secupress-summary-header -->

	<div class="secupress-flex secupress-wrap secupress-pt1 secupress-pb1">
		<div class="secupress-col-1-2 secupress-flex secupress-landscape-blob">
			<div class="secupress-col">
				<i class="icon-schedule" aria-hidden="true"></i>
			</div>
			<div class="secupress-col">
				<p class="secupress-blob-title"><?php esc_html_e( 'Schedule', 'secupress' ); ?></p>
				<p class="secupress-blob-desc"><?php _e( 'Keep up the good security by scheduling your next scans. No need to do it manually each week anymore…', 'secupress' ); ?></p>
			</div>
		</div>
		<div class="secupress-col-1-2 secupress-flex secupress-landscape-blob">
			<div class="secupress-col">
				<i class="icon-information" aria-hidden="true"></i>
			</div>
			<div class="secupress-col">
				<p class="secupress-blob-title"><?php esc_html_e( 'Alerts', 'secupress' ); ?></p>
				<p class="secupress-blob-desc"><?php _e( 'Receive an alert by e-mail, SMS, or even Slack each time we think it’s necessary for your security.', 'secupress' ); ?></p>
			</div>
		</div>
		<div class="secupress-col-1-2 secupress-flex secupress-landscape-blob">
			<div class="secupress-col">
				<i class="icon-firewall" aria-hidden="true"></i>
			</div>
			<div class="secupress-col">
				<p class="secupress-blob-title"><?php esc_html_e( 'Firewall', 'secupress' ); ?></p>
				<p class="secupress-blob-desc"><?php _e( 'Be pro-active and lock IPs or requests you think that could be bad for you. We already lock some by default.', 'secupress' ); ?></p>
			</div>
		</div>
		<div class="secupress-col-1-2 secupress-flex secupress-landscape-blob">
			<div class="secupress-col">
				<i class="icon-logs" aria-hidden="true"></i>
			</div>
			<div class="secupress-col">
				<p class="secupress-blob-title"><?php esc_html_e( 'Logs', 'secupress' ); ?></p>
				<p class="secupress-blob-desc"><?php _e( 'Enter the matrix and take a look at the requests done on your website.', 'secupress' ); ?></p>
			</div>
		</div>
	</div>
</div><!-- .secupress-pro-summary -->
<?php } ?>
