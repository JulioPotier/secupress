<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Keep only scans with "bad" and "warning" status.
$bad_scan_results = array_merge( $bad_scans, $warning_scans );	// `array( $class_name_part_lower => $status )`
$fix_actions      = array();									// `array( $class_name_part_lower => array( $fix_action, $fix_action ) )`

/**
 * Keep only scanners where:
 * - it needs a manual fix,
 * - or, is not fixable by SecuPress (it needs the user to go to the hoster administration interface),
 * - or, is fixable only with the Pro Version (and we use the Free version),
 * - or, an automatic fix has been attempted (but maybe it's an old result),
 * - or, the scan status is a "warning",
 * Also, require the scan files + get the "fix actions".
 */
foreach ( $secupress_tests as $module_name => $class_name_parts ) {

	$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
	$class_name_parts = array_intersect_key( $class_name_parts, $bad_scan_results );

	// Only "bad" and "warning" status.
	if ( ! $class_name_parts ) {
		unset( $secupress_tests[ $module_name ] );
		continue;
	}

	$secupress_tests[ $module_name ] = $class_name_parts;

	foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) {
		if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ], $bad_scan_results[ $class_name_part_lower ] );
			continue;
		}

		secupress_require_class( 'scan', $class_name_part );

		$class_name       = 'SecuPress_Scan_' . $class_name_part;
		$current_test     = $class_name::get_instance();
		$is_fixable       = $current_test->is_fixable();
		$this_fix_actions = $current_test->need_manual_fix();

		// Those that need a manual fix.
		if ( is_array( $this_fix_actions ) ) {
			// Store the "fix actions".
			if ( $this_fix_actions ) {
				$fix_actions[ $class_name_part_lower ] = $this_fix_actions;
			} else {
				// Doesn't need to be fixed, the scan is simply not up to date.
				unset( $secupress_tests[ $module_name ][ $class_name_part_lower ], $bad_scan_results[ $class_name_part_lower ] );
			}
		}
		// Not fixable + Pro.
		elseif ( false === $is_fixable || 'pro' === $is_fixable && ! secupress_is_pro() ) {
			// OK.
		}
		// An automatic fix has been attempted.
		elseif ( ! empty( $fixes[ $class_name_part_lower ] ) ) {
			// OK.
		}
		// A "bad" scan status means the user didn't try to fix it.
		elseif ( 'warning' !== $bad_scan_results[ $class_name_part_lower ] ) {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ], $bad_scan_results[ $class_name_part_lower ] );
		}
	}
}

$secupress_tests = array_filter( $secupress_tests );

// Move along, move along...
if ( ! $secupress_tests ) {
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
	$nb_actions    = count( $bad_scan_results );
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

	foreach ( $secupress_tests as $module_name => $class_name_parts ) {

		foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) {
			$class_name   = 'SecuPress_Scan_' . $class_name_part;
			$current_test = $class_name::get_instance();
			$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners&step=3#' . $class_name_part ) ) );
			$module_icon  = ! empty( $modules[ $module_name ]['icon'] ) ? $modules[ $module_name ]['icon'] : '';

			// Scan.
			$scanner        = isset( $scanners[ $class_name_part_lower ] ) ? $scanners[ $class_name_part_lower ] : array();
			$scan_status    = $scanner['status'];
			$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_scanner_' . $class_name_part );

			// Fix.
			$fix_result = ! empty( $fixes[ $class_name_part_lower ] ) ? $fixes[ $class_name_part_lower ] : array();
			$fix_status = ! empty( $fix_result['status'] ) ? $fix_result['status'] : true;

			// State.
			$has_actions            = ! empty( $fix_actions[ $class_name_part_lower ] );
			$needs_pro              = 'pro' === $current_test->is_fixable() && ! secupress_is_pro();
			$is_fixable             = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();
			$not_fixable_by_sp      = false === $current_test->is_fixable();
			$is_fixable_with_action = $is_fixable && $has_actions;

			// Row css class.
			$row_css_class  = 'secupress-item-' . $class_name_part;
			$row_css_class .= ' status-' . sanitize_html_class( $scan_status );
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

				<div id="secupress-mf-content-<?php echo $class_name_part; ?>" class="secupress-mf-content <?php echo $row_css_class; ?>" data-scan-url="<?php echo esc_url( $scan_nonce_url ); ?>">

					<?php if ( $is_fixable_with_action ) { ?>
					<form class="secupress-item-content" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php } else { ?>
					<div class="secupress-item-content">
					<?php } ?>

						<p class="secupress-ic-title">
							<?php _e( 'How to Fix this issue', 'secupress' ); ?>
						</p>

						<p class="secupress-ic-desc">
							<?php
							// Case 1: needs Pro, or can be fixed manually (form).
							if ( $needs_pro || $has_actions ) {
								echo wp_kses( $current_test->more_fix, $allowed_tags );
							}
							// Case 2: not fixable by SecuPress (example: DB password).
							elseif ( ! $is_fixable ) {
								if ( ! empty( $scanner['msgs'] ) ) {
									$message = secupress_format_message( $scanner['msgs'], $class_name_part );
								} else {
									$message = $current_test->more_fix;
								}
								echo wp_kses( $message, $allowed_tags );
							}
							// Automatic fix failed.
							elseif ( $fix_result ) {
								// Case 3: the fix has been applied but the flaw persists (bug?), or the flaw reappeared (example: the user enabled debug in wp-config.php).
								if ( 'good' === $fix_status && ! empty( $scanner['msgs'] ) ) {
									$message = secupress_format_message( $scanner['msgs'], $class_name_part );
								}
								// Case 4: the fix couldn't be applied (example: `.htaccess` not writable).
								elseif ( ! empty( $fix_result['msgs'] ) ) {
									$message = secupress_format_message( $fix_result['msgs'], $class_name_part );
								}
								// Fallback 1, shouldn't happen: display the scan message.
								elseif ( ! empty( $scanner['msgs'] ) ) {
									$message = secupress_format_message( $scanner['msgs'], $class_name_part );
								}
								// Fallback 2, shouldn't happen: display the "more fix" text.
								else {
									$message = $current_test->more_fix;
								}
								echo wp_kses( $message, $allowed_tags );
							}
							// Case 4: the scan status is a "warning", and no fix have been tried yet (example: unable to reach homepage).
							elseif ( 'warning' === $scan_status && ! empty( $scanner['msgs'] ) ) {
								echo wp_kses( secupress_format_message( $scanner['msgs'], $class_name_part ), $allowed_tags );
							}
							// Fallback 3, shouldn't happen: display the "more fix" text.
							else {
								echo wp_kses( $current_test->more_fix, $allowed_tags );
							}
							?>
						</p>

						<?php if ( $is_fixable_with_action ) { ?>
							<div class="secupress-ic-fix-actions">
								<?php $current_test->get_required_fix_action_template_parts( $fix_actions[ $class_name_part_lower ] ); ?>
							</div>
						<?php } ?>

						<div class="secupress-row-actions secupress-flex secupress-flex-spaced secupress-mt2">
							<p class="secupress-action-doc">
								<a href="<?php echo $current_test::DOC_URL; ?>" class="secupress-button secupress-button-mini shadow" target="_blank" title="<?php _e( 'Open in a new window', 'secupress' ); ?>">
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
										<span class="text"><?php _e( 'Fix it and continue', 'secupress' ); ?></span>
									</button>
								<?php } elseif ( $needs_pro ) { ?>
									<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ); ?>" class="secupress-button secupress-button-tertiary secupress-button-getpro shadow">
										<span class="icon">
											<i class="icon-secupress-simple bold" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Get PRO', 'secupress' ); ?></span>
									</a>
								<?php } elseif ( $not_fixable_by_sp || 'cantfix' === $fix_status ) { ?>
									<a href="<?php echo esc_url( $scan_nonce_url ); ?>" class="secupress-button secupress-button-primary secupress-button-manual-scanit shadow">
										<span class="icon">
											<i class="icon-check" aria-hidden="true"></i>
										</span>
										<span class="text"><?php _e( 'Done', 'secupress' ); ?></span>
									</a>
								<?php } ?>
							</p>
						</div>

					<?php if ( $is_fixable_with_action ) { ?>
					</form><!-- .secupress-item-content -->
					<?php } else { ?>
					</div><!-- .secupress-item-content -->
					<?php } ?>

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
		} // Eo foreach $class_name_parts.

	} // Eo foreach $secupress_tests.
	?>
</div><!-- .secupress-tests -->
