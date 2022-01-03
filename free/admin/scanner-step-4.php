<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$modules          = secupress_get_modules();
$scanned_items    = secupress_get_scan_results();
$nb_good_scans    = 0;
$nb_bad_scans     = 0;
$nb_warning_scans = 0;
$grade            = secupress_get_scanner_counts( 'grade' );
$old_report       = secupress_get_old_report();
$old_grade        = $old_report['grade'];
$this_good_scans  = array();

foreach ( $scanned_items as $class_name_part => $details ) {
	if ( isset( $old_report['report'][ $class_name_part ] ) && 'good' === $details['status'] && 'good' !== $old_report['report'][ $class_name_part ]['status'] ) {
		$this_good_scans[ $class_name_part ] = $details;
		if ( 'bad' === $old_report['report'][ $class_name_part ]['status'] ) {
			++$nb_bad_scans;
		} else {
			++$nb_warning_scans;
		}
	}
	if ( 'good' === $details['status'] ) {
		++$nb_good_scans;
	}
}
?>

<div id="secupress-tests" class="secupress-tests secupress-is-finish-report secupress-box-shadow">

	<div class="secupress-summary-header secupress-section-dark">
		<div class="secupress-flex">
			<div class="secupress-col-logo">
				<?php echo secupress_get_logo( array( 'width' => 81 ) ); ?>
			</div>
			<div class="secupress-col-summary-text">

				<?php
				// Display a "bravo" message only if there is something fixed.
				if ( $nb_good_scans ) {
					?>
					<p class="secupress-text-medium secupress-mb0"><?php printf( __( 'Bravo! You fixed %1$d of %2$d.', 'secupress' ), $nb_good_scans, count( $scanned_items ) ); ?></p>
					<?php
				} else {
					?>
					<p class="secupress-text-medium secupress-mb0"><?php printf( __( 'Nothing fixed yet, %d left.', 'secupress' ), count( $scanned_items ) ); ?></p>
					<?php
				}
				if ( secupress_get_module_option( 'advanced-settings_grade-system', true, 'welcome' ) ) {
				?>
				<p>
					<?php
					// Display a "grade ent from to" message only if it's better.
					if ( $old_grade === $grade ) {
						printf( __( 'Your grade is still %s. ', 'secupress' ), $grade );
					} else {
						printf( __( 'Your grade went from %1$s to %2$s. ', 'secupress' ), $old_grade, $grade );
					}

					// Display the pre-message to show what has just been fixed.
					if ( $nb_bad_scans || $nb_warning_scans ) {
						_e( 'You fixed: ', 'secupress' );
					}
					?>
				</p>
				<?php } ?>
				<div class="secupress-flex secupress-flex-spaced">
					<div>
						<?php
						if ( $nb_bad_scans || $nb_warning_scans ) {
							?>
							<ul class="secupress-chart-legend">
								<?php
								if ( $nb_bad_scans ) {
									?>
									<li class="status-bad">
										<span class="secupress-carret"></span>
										<?php printf( __( '%d Bad', 'secupress' ), $nb_bad_scans ); ?>
										<span class="secupress-count-bad"></span>
									</li>
									<?php
								}

								if ( $nb_warning_scans ) {
									?>
									<li class="status-warning">
										<span class="secupress-carret"></span>
										<?php printf( __( '%d Warning', 'secupress' ), $nb_warning_scans ); ?>
										<span class="secupress-count-warning"></span>
									</li>
									<?php
								}
								?>
							</ul>
							<?php
						}
						?>
					</div>
					<?php if ( $nb_bad_scans || $nb_warning_scans ) { ?>
						<p>
							<button class="secupress-button secupress-button-ghost secupress-button-mini hide-is-no-js" type="button" data-target="secupress-summaries" data-trigger="slidetoggle" title="<?php esc_attr_e( 'Show/hide the details of scanned items in your report', 'secupress' ); ?>">
								<span class="icon">
									<i class="secupress-icon-angle-down" aria-hidden="true"></i>
								</span>
								<span class="text" aria-hidden="true">
									<span class="hidden-when-activated">
										<?php _e( 'See all fixed issues', 'secupress' ); ?>
									</span>
									<span class="visible-when-activated">
										<?php _e( 'Hide all fixed issues', 'secupress' ); ?>
									</span>
								</span>
							</button>
						</p>
					<?php } ?>
				</div>
			</div>
		</div>
	</div><!-- .secupress-summary-header -->

	<div id="secupress-summaries" class="secupress-summaries hide-if-js">
		<?php
		foreach ( $secupress_tests as $module_name => $class_name_parts ) {
			$i = 0;

			$module_title     = ! empty( $modules[ $module_name ]['title'] )              ? $modules[ $module_name ]['title']              : '';
			$module_summary   = ! empty( $modules[ $module_name ]['summaries']['small'] ) ? $modules[ $module_name ]['summaries']['small'] : '';
			$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );

			foreach ( $class_name_parts as $option_name => $class_name_part ) {
				if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
					unset( $class_name_parts[ $option_name ] );
					continue;
				}

				secupress_require_class( 'scan', $class_name_part );
			}

			// For this priority, order the scans by status: 'good', 'warning', 'good', 'new'.
			$class_name_parts = array_intersect_key( $class_name_parts, $good_scans );
			$class_name_parts = array_intersect_key( $class_name_parts, $this_good_scans );

			if ( ! $class_name_parts ) {
				continue;
			}
			?>
			<div class="secupress-scans-group secupress-group-<?php echo $module_name; ?>">

				<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

					<div class="secupress-sgh-name">
						<i class="secupress-icon-user-login" aria-hidden="true"></i>
						<p class="secupress-sgh-title"><?php echo $module_title; ?></p>
						<p class="secupress-sgh-description"><?php echo $module_summary; ?></p>
					</div>

					<div class="secupress-sgh-actions secupress-flex secupress-flex-top">
						<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-<?php echo $module_name; ?>">
							<i class="secupress-icon-angle-up" aria-hidden="true"></i>
							<span class="screen-reader-text"><?php _e( 'Show/hide panel', 'secupress' ); ?></span>
						</button>
					</div>

				</div><!-- .secupress-sg-header -->

				<div id="secupress-group-content-<?php echo $module_name; ?>" class="secupress-sg-content">
					<?php
					foreach ( $class_name_parts as $option_name => $class_name_part ) {
						++$i;
						$class_name   = 'SecuPress_Scan_' . $class_name_part;
						$current_test = $class_name::get_instance();
						$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners#' . $class_name_part ) ) );
						$is_fixable   = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();

						// Scan.
						$scanner        = isset( $scanners[ $option_name ] ) ? $scanners[ $option_name ] : array();
						$scan_status    = ! empty( $scanner['status'] ) ? $scanner['status'] : 'notscannedyet';
						$scan_nonce_url = 'secupress_scanner_' . $class_name_part;
						$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), $scan_nonce_url );
						$scan_message   = '&#175;';

						if ( ! empty( $scanner['msgs'] ) ) {
							$scan_message = secupress_format_message( $scanner['msgs'], $class_name_part );
						}

						// Fix.
						$fix             = ! empty( $fixes[ $option_name ] ) ? $fixes[ $option_name ] : array();
						$fix_status_text = ! empty( $fix['status'] ) && 'good' !== $fix['status'] ? secupress_status( $fix['status'] ) : '';
						$fix_nonce_url   = 'secupress_fixit_' . $class_name_part;
						$fix_nonce_url   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), $fix_nonce_url );
						$fix_message     = '';

						if ( ! empty( $fix['msgs'] ) && 'good' !== $scan_status ) {
							$scan_message = secupress_format_message( $fix['msgs'], $class_name_part );
						}

						// Row css class.
						$row_css_class  = ' status-' . sanitize_html_class( $scan_status );
						$row_css_class .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
						$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
						$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
						$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';

						// To-check: are all status here? ////.
						switch ( $scan_status ) {

							case 'bad' :
								$icon_slug = 'cross-o';
								$scan_status_word = esc_html__( 'Not fixed', 'secupress' );
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

						<div class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> status-all <?php echo $row_css_class; ?>" id="<?php echo $class_name_part; ?>">

							<div class="secupress-flex">

								<p class="secupress-item-status secupress-status-mini">
									<span class="secupress-dot-<?php echo $scan_status; ?>"></span>
								</p>

								<p class="secupress-item-title"><?php echo $scan_message; ?></p>

								<p class="secupress-row-actions">
									<span class="secupress-status secupress-status-<?php echo sanitize_html_class( $scan_status ); ?>">
										<i class="secupress-icon-<?php echo $icon_slug; ?>" aria-hidden="true"></i>
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
		<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced" id="secupress-step-content-footer">
			<?php
			$export_pdf_btn = '<span class="icon">
					<i class="secupress-icon-file-pdf-o" aria-hidden="true"></i>
				</span>
				<span class="text">
					' . __( 'Export as PDF', 'secupress' ) . '
				</span>';
			?>
			<p>
				<?php
				if ( secupress_is_pro() ) {
					?>
					<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export_pdf' ), 'secupress_export_pdf' ) ); ?>" title="<?php esc_attr_e( 'Export this report as PDF file.', 'secupress' ); ?>" class="secupress-button shadow">
						<?php echo $export_pdf_btn; ?>
					</a>
					<?php
				} else {
					?>
					<a href="<?php echo esc_url( secupress_admin_url( 'get-pro' ) ) ?>" type="button" title="<?php esc_attr_e( 'Get the Pro Version to export this report as PDF file.', 'secupress' ); ?>" target="_blank" class="secupress-button disabled shadow">
						<?php echo $export_pdf_btn; ?>
					</a>
					<br>
					<span class="secupress-get-pro-version">
						<?php printf( __( 'Available in <a href="%s" target="_blank">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get-pro' ) ) ); ?>
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
				<p class="secupress-farther-desc"><?php _e( 'Perfect the security of your website with our dedicated modules.', 'secupress' ); ?></p>
			</div>
			<div class="secupress-col secupress-col-action">
				<a href="<?php echo esc_url( secupress_admin_url( 'modules' ) ); ?>" class="secupress-rich-link secupress-current">
					<span class="secupress-label-with-icon">
						<i aria-hidden="true" class="secupress-icon-cogs rounded"></i>
						<span class="secupress-upper"><?php printf(
							/** Translators: %s is the plugin name. */
							__( '%s modules', 'secupress' ),
							SECUPRESS_PLUGIN_NAME
						); ?></span>
						<span class="secupress-description"><?php esc_html_e( 'Fine-tune your security', 'secupress' ); ?></span>
					</span>
				</a>
			</div>
		</div>
		<div class="secupress-flex">
			<div class="secupress-col">
				<p class="secupress-farther-title"><?php esc_html_e( 'Manage your recurring scans', 'secupress' ); ?></p>
				<p class="secupress-farther-desc"><?php sprintf( esc_html__( 'Let %s scan your website when you are away by using scheduled scans.', 'secupress' ), SECUPRESS_PLUGIN_NAME ); ?></p>
			</div>
			<div class="secupress-col secupress-col-action">
				<a href="<?php echo esc_url( secupress_admin_url( 'modules' ) ); ?>&amp;module=schedules" class="secupress-rich-link secupress-current">
					<span class="secupress-label-with-icon">
						<i aria-hidden="true" class="secupress-icon-calendar rounded"></i>
						<span class="secupress-upper"><?php esc_html_e( 'Schedule Scans', 'secupress' ); ?></span>
						<span class="secupress-description"><?php esc_html_e( 'Schedule your recurring scans', 'secupress' ); ?></span>
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
					<?php echo secupress_get_logo( array( 'width' => 81 ) ); ?>
				</div>
				<div class="secupress-col-summary-text secupress-flex secupress-flex-spaced">
					<p class="secupress-text-medium secupress-mb0">
						<?php _e( 'Get a better score and unlock all features', 'secupress' ); ?>
					</p>
					<p class="secupress-p1">
						<a href="<?php echo esc_url( secupress_admin_url( 'get-pro' ) ); ?>" class="secupress-button secupress-button-tertiary secupress-button-getpro">
							<span class="icon">
								<i class="secupress-icon-secupress-simple" aria-hidden="true"></i>
							</span>
							<span class="text">
								<?php _e( 'Get Pro', 'secupress' ); ?>
							</span>
						</a>
					</p>
				</div>
			</div>
		</div><!-- .secupress-summary-header -->

		<?php secupress_print_pro_advantages(); ?>

	</div><!-- .secupress-pro-summary -->
	<?php
}
?>
