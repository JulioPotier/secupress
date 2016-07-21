<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Keep only scans with "bad" and "warning" status.
$fix_actions = array_merge( $bad_scans, $warning_scans );	// `array( $class_name_part_lower => $status )`, will become `array( $class_name_part_lower => array( $fix_action, $fix_action ), $class_name_part_lower => false )`.

/**
 * Add scanners where the fix failed.
 * Also, make sure all fixes have a status, we'll need it.
 */
foreach ( $fixes as $class_name_part_lower => $fix ) {
	$failed = false;

	if ( ! empty( $fix['status'] ) ) {
		// We have the status.
		$failed = 'good' !== $fix['status'];
	} elseif ( ! empty( $fix['msgs'] ) ) {
		$fixes[ $class_name_part_lower ]['status'] = 'good';

		// Get the status from the message codes.
		foreach ( $fix['msgs'] as $code => $msg_atts ) {
			if ( $code >= 100 ) {
				$failed = true;
				$fixes[ $class_name_part_lower ]['status'] = true; // No need to set the real status because we will test against 'good'.
				break;
			}
		}
	}

	if ( $failed && empty( $fix_actions[ $class_name_part_lower ] ) ) {
		// Add this scanner to the list.
		$fix_actions[ $class_name_part_lower ] = true;
	}
}

/**
 * Keep only scanners where:
 * - it needs a manual fix,
 * - or, the scan status is a "warning",
 * - or, the automatic fix failed,
 * - or, is fixable only with the Pro Version (and we use the Free version),
 * - or, is not fixable by SecuPress (it needs the user to go to the hoster administration interface).
 * Also, require the scan files + get the "fix actions".
 */
foreach ( $secupress_tests as $module_name => $class_name_parts ) {

	$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
	$class_name_parts = array_intersect_key( $class_name_parts, $fix_actions );

	// Only those selected.
	if ( ! $class_name_parts ) {
		unset( $secupress_tests[ $module_name ] );
		continue;
	}

	$secupress_tests[ $module_name ] = $class_name_parts;

	foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) {
		if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ], $fix_actions[ $class_name_part_lower ] );
			continue;
		}

		secupress_require_class( 'scan', $class_name_part );
		$class_name       = 'SecuPress_Scan_' . $class_name_part;
		$current_test     = $class_name::get_instance();
		$is_fixable       = $current_test->is_fixable();
		$this_fix_actions = $current_test->need_manual_fix();
		$this_fix_result  = ! empty( $fixes[ $class_name_part_lower ] ) ? $fixes[ $class_name_part_lower ] : array();

		// Those that need a manual fix.
		if ( $this_fix_actions ) {
			// Store the "fix actions".
			$fix_actions[ $class_name_part_lower ] = $this_fix_actions;
		}
		// Warning.
		elseif ( 'bad' !== $fix_actions[ $class_name_part_lower ] ) {
			$fix_actions[ $class_name_part_lower ] = false;
		}
		// Not fixable + Pro.
		elseif ( false === $is_fixable || 'pro' === $is_fixable && ! secupress_is_pro() ) {
			$fix_actions[ $class_name_part_lower ] = false;
		}
		// Fix failed.
		elseif ( ! empty( $this_fix_result['status'] ) && 'good' !== $this_fix_result['status'] ) {
			$fix_actions[ $class_name_part_lower ] = false;
		} else {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ], $fix_actions[ $class_name_part_lower ] );
		}
	}
}

$secupress_tests = array_filter( $secupress_tests );

// Move along, move along...
if ( ! $fix_actions ) {
	?>
	<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
		<p class="secupress-step-title"><?php _e( 'Nothing to do here' ); ?></p>
		<p class="secupress-flex">
			<a href="<?php echo esc_url( secupress_admin_url( 'scanners' ) ); ?>&amp;step=4" class="secupress-button shadow light">
				<span class="icon">
					<i class="icon-cross" aria-hidden="true"></i>
				</span>
				<span class="text"><?php _e( 'Next step', 'secupress' ); ?></span>
			</a>
		</p>
	</div>
	<?php
	return;
}

?>
<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
	<?php
	$nb_actions    = count( $fix_actions );
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
			<span class="text">' . __( 'Ignore this step', 'secupress' ) . '</span>
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
	$modules      = secupress_get_modules();
	$hidden_class = '';

	foreach ( $secupress_tests as $module_name => $class_name_parts ) :

		foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) :
			$class_name   = 'SecuPress_Scan_' . $class_name_part;
			$current_test = $class_name::get_instance();
			$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners&step=3#' . $class_name_part ) ) );
			$module_icon  = ! empty( $modules[ $module_name ]['icon'] ) ? $modules[ $module_name ]['icon'] : '';

			// Scan.
			$scanner        = isset( $scanners[ $class_name_part_lower ] ) ? $scanners[ $class_name_part_lower ] : array();
			$scan_status    = ! empty( $scanner['status'] ) ? $scanner['status'] : 'notscannedyet';
			$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_scanner_' . $class_name_part );

			// Fix.
			$fix_result = ! empty( $fixes[ $class_name_part_lower ] ) ? $fixes[ $class_name_part_lower ] : array();

			// State.
			$needs_pro              = 'pro' === $current_test->is_fixable() && ! secupress_is_pro();
			$has_actions            = (bool) $fix_actions[ $class_name_part_lower ];
			$is_fixable             = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();
			$is_fixable_with_action = $is_fixable && $has_actions;
			$is_scan_warning        = 'warning' === $scan_status;
			$fix_failed             = $is_fixable && ! $has_actions && ! empty( $fix_result['status'] ) && 'good' !== $fix_result['status'];

			// Row css class.
			$row_css_class  = ' status-' . sanitize_html_class( $scan_status );
			$row_css_class .= $is_fixable_with_action ? ' fixable' : ' not-fixable';
			?>
			<div class="secupress-manual-fix secupress-manual-fix-<?php echo $module_name; ?> secupress-group-item-<?php echo $class_name_part; ?><?php echo $hidden_class; ?>">

				<div class="secupress-mf-header secupress-flex-spaced<?php echo $needs_pro ? ' secupress-is-only-pro' : '' ?>">

					<div class="secupress-mfh-name secupress-flex">
						<span class="secupress-header-dot">
							<span class="secupress-dot-warning"></span>
						</span>
						<p class="secupress-mfh-title"><?php echo $current_test->title; ?></p>

						<?php if ( ! $needs_pro ) { ?>

							<i class="icon-<?php echo $module_icon; ?>" aria-hidden="true"></i>

						<?php } else { ?>

							<div class="secupress-mfh-pro">
								<p class="secupress-get-pro-version">
									<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
								</p>
							</div>

						<?php } ?>
					</div>

				</div><!-- .secupress-mf-header -->

				<div id="secupress-mf-content-<?php echo $class_name_part; ?>" class="secupress-mf-content secupress-item-<?php echo $class_name_part; ?> status-all <?php echo $row_css_class; ?>">

					<?php if ( $is_fixable_with_action ) : ?>
					<form class="secupress-item-content" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php else : ?>
					<div class="secupress-item-content">
					<?php endif; ?>

						<p class="secupress-ic-title">
							<?php _e( 'How to Fix this issue', 'secupress' ); ?>
						</p>

						<p class="secupress-ic-desc">
							<?php
							if ( $fix_failed && ! empty( $fix['msgs'] ) ) {
								$message = secupress_format_message( $fix['msgs'], $class_name_part );
								echo wp_kses( $message, $allowed_tags );
							} elseif ( $is_scan_warning && ! empty( $scanner['msgs'] ) ) {
								$message = secupress_format_message( $scanner['msgs'], $class_name_part );
								echo wp_kses( $message, $allowed_tags );
							} else {
								echo wp_kses( $current_test->more_fix, $allowed_tags );
							}
							?>
						</p>

						<?php if ( $is_fixable_with_action ) : ?>
							<div class="secupress-ic-fix-actions">
								<?php
								$fix_actions[ $class_name_part_lower ] = $current_test->get_required_fix_action_template_parts( $fix_actions[ $class_name_part_lower ] );

								echo implode( '', $fix_actions[ $class_name_part_lower ] );
								$current_test->get_fix_action_fields( array_keys( $fix_actions[ $class_name_part_lower ] ) );

								unset( $fix_actions[ $class_name_part_lower ] );
								?>
							</div>
						<?php endif; ?>

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
								<?php if ( $is_fixable_with_action ) { ?>
									<button type="submit" class="secupress-button secupress-button-primary secupress-button-manual-fixit shadow">
										<span class="icon">
											<i class="icon-check" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Fix it', 'secupress' ); ?></span>
									</button>
								<?php } elseif ( $needs_pro ) { ?>
									<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ); ?>" class="secupress-button secupress-button-tertiary secupress-button-getpro shadow">
										<span class="icon">
											<i class="icon-secupress-simple bold" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Get PRO', 'secupress' ); ?></span>
									</a>
								<?php } ?>
							</p>
						</div>

					<?php if ( $is_fixable_with_action ) : ?>
					</form><!-- .secupress-item-content -->
					<?php else : ?>
					</div><!-- .secupress-item-content -->
					<?php endif; ?>

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

	endforeach;
	?>
</div><!-- .secupress-tests -->
