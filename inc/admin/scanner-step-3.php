<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Actions the user needs to perform for a fix.
$fix_actions = SecuPress_Scan::get_and_delete_fix_actions();
$modules     = secupress_get_modules();
?>
<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
	<?php
	$nb_actions    = count( $bad_scans ) + count( $warning_scans );
	$page_title    = sprintf( _n( 'This action require your attention', 'These %d actions require your attention', $nb_actions, 'secupress' ), $nb_actions );
	$steps_counter =
		'<span class="secupress-step-by-step secupress-flex hide-if-no-js">
			<span class="text step3-advanced-text">
				' . sprintf( __( '%s of %d', 'secupress' ), '1</span><span class="text">', $nb_actions ) . '
			</span>
		</span>';
	$main_button   =
		'<a href="' . esc_url( secupress_admin_url( 'scanners' ) ) . '&step=4" class="secupress-button shadow light">
			<span class="icon">
				<i class="icon-cross" aria-hidden="true"></i>
			</span>
			<span class="text">' . __( 'Ignore this step', 'secupress') . '</span>
		</a>';
	?>
	<p class="secupress-step-title"><?php echo $page_title; ?></p>
	<p class="secupress-flex">
		<?php echo $steps_counter; ?>
		<?php echo $main_button; ?>
	</p>
</div>

<div id="secupress-tests" class="secupress-tests">
	<?php
	$hidden_class = '';

	foreach ( $secupress_tests as $module_name => $class_name_parts ) {

		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );

		foreach ( $class_name_parts as $option_name => $class_name_part ) {
			if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
				unset( $class_name_parts[ $option_name ] );
				continue;
			}

			secupress_require_class( 'scan', $class_name_part );
		}

		// For this module, order the scans by status: 'warning', 'bad'.
		$this_module_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
		$this_module_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
		$class_name_parts          = array_merge( $this_module_warning_scans, $this_module_bad_scans );
		unset( $this_module_bad_scans, $this_module_warning_scans );

		foreach ( $class_name_parts as $option_name => $class_name_part ) :
			$class_name   = 'SecuPress_Scan_' . $class_name_part;
			$current_test = $class_name::get_instance();
			$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners&step=3#' . $class_name_part ) ) );
			$is_fixable   = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();
			$is_only_pro  = 'pro' === $current_test->is_fixable() && ! secupress_is_pro();
			$module_icon  = ! empty( $modules[ $module_name ]['icon'] ) ? $modules[ $module_name ]['icon'] : '';

			// Scan.
			$scanner        = isset( $scanners[ $option_name ] ) ? $scanners[ $option_name ] : array();
			$scan_status    = ! empty( $scanner['status'] ) ? $scanner['status'] : 'notscannedyet';
			$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_scanner_' . $class_name_part );

			// Fix.
			$fix           = ! empty( $fixes[ $option_name ] ) ? $fixes[ $option_name ] : array();
			$fix_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_fixit_' . $class_name_part );

			// Row css class.
			$row_css_class  = ' status-' . sanitize_html_class( $scan_status );
			$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
			$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
			$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';
			?>
			<div class="secupress-manual-fix secupress-manual-fix-<?php echo $module_name; ?> secupress-group-item-<?php echo $class_name_part; ?><?php echo $hidden_class; ?>">

				<div class="secupress-mf-header secupress-flex-spaced<?php echo $is_only_pro ? ' secupress-is-only-pro' : '' ?>">

					<div class="secupress-mfh-name secupress-flex">
						<span class="secupress-header-dot">
							<span class="secupress-dot-warning"></span>
						</span>
						<p class="secupress-mfh-title"><?php echo $current_test->title; ?></p>

						<?php if ( $is_only_pro ) { ?>

							<div class="secupress-mfh-pro">
								<p class="secupress-get-pro-version">
									<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
								</p>
							</div>

						<?php } else { ?>

							<i class="icon-<?php echo $module_icon; ?>" aria-hidden="true"></i>

						<?php } ?>
					</div>

				</div><!-- .secupress-mf-header -->

				<div id="secupress-mf-content-<?php echo $class_name_part; ?>" class="secupress-mf-content secupress-item-<?php echo $class_name_part; ?> status-all <?php echo $row_css_class; ?>">

					<div class="secupress-item-content">

						<p class="secupress-ic-title">
							<?php _e( 'How to Fix this issue', 'secupress' ); ?>
						</p>

						<p class="secupress-ic-desc">
							<?php echo wp_kses( $current_test->more_fix, $allowed_tags ); ?>
						</p>

						<div class="secupress-ic-fix-actions">
							<?php
							$fix_actions = $current_test->get_required_fix_action_template_parts( $fix_actions );
							var_dump( $fix_actions ); //// toujours 0 :/ Normal, on ne peut plus utiliser ça, il faut créer un nouveau système.
							?>
						</div>

						<div class="secupress-row-actions secupress-flex secupress-flex-spaced secupress-mt2">
							<p class="secupress-action-doc">
								<a href="<?php echo $current_test::DOC_URL; ?>" class="secupress-button secupress-button-mini shadow">
									<span class="icon">
										<i class="icon-file-text" aria-hidden="true"></i>
									</span>
									<span class="text"><?php _e( 'Read the documentation', 'secupress' ); ?></span>
								</a>
								<?php if ( secupress_is_pro() ) { ?>
									<a href="#" class="secupress-button secupress-button-mini secupress-button-support light shadow"><?php // URL ////. ?>
										<span class="icon">
											<i class="icon-ask" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Ask for support', 'secupress' ); ?></span>
									</a>
								<?php } ?>
							</p>
							<p class="secupress-actions">
								<a href="<?php echo esc_url( secupress_admin_url( 'scanners' ) ); ?>&amp;step=4" class="secupress-button secupress-button-ignoreit hide-is-no-js shadow light" data-parent="secupress-group-item-<?php echo $class_name_part; ?>">
									<span class="icon">
										<i class="icon-cross" aria-hidden="true"></i>
									</span>
									<span class="text"><?php _e( 'Ignore it', 'secupress' ); ?></span>
								</a>
								<?php if ( $is_fixable && $current_test->need_manual_fix() ) { ?>
									<a href="<?php echo esc_url( $fix_nonce_url ); ?>" class="secupress-button secupress-button-primary secupress-button-fixit shadow">
										<span class="icon">
											<i class="icon-check" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Fix it', 'secupress' ); ?></span>
									</a>
								<?php } elseif ( $is_fixable && ! $current_test->need_manual_fix() ) { ?>
									<a href="<?php echo esc_url( $fix_nonce_url ); ?>" class="secupress-button secupress-button-primary secupress-button-fixit shadow">
										<span class="icon">
											<i class="icon-check" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Retry to fix', 'secupress' ); ?></span>
									</a>
								<?php } elseif ( $is_only_pro ) { ?>
									<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ); ?>" class="secupress-button secupress-button-tertiary secupress-button-getpro shadow">
										<span class="icon">
											<i class="icon-secupress-simple bold" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Get PRO', 'secupress' ); ?></span>
									</a>
								<?php } ?>
							</p>
						</div>

					</div><!-- .secupress-item-content -->

					<div class="secupress-item-details" id="details-<?php echo $class_name_part; ?>">
						<div class="secupress-flex">
							<span class="secupress-details-icon">
								<i class="icon-i" aria-hidden="true"></i>
							</span>
							<p class="details-content"><?php echo wp_kses( $current_test->more, $allowed_tags ); ?></p>
							<span class="secupress-placeholder"></span>
						</div>
					</div>

				</div><!-- .secupress-mf-content -->
			</div><!-- .secupress-manual-fix -->
			<?php
			$hidden_class = ' hide-if-js';
		endforeach;
	}
	?>
</div><!-- .secupress-tests -->
