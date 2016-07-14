<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$modules                = secupress_get_modules();
?>
<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">

	<?php
	$page_title  = sprintf( __( 'These %d actions require your attention', 'secupress' ), 12/*//// dyn */ );
	$main_button =
	'<a href="' . secupress_admin_url( 'scanners' ) . '&step=4" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
		<span class="hide-if-no-js">
			<span class="text">1</span>////
			<span class="text">12</span>
		</span>
		<span class="icon">
			<i class="icon-cross" aria-hidden="true"></i>
		</span>
		<span class="text">' . esc_html__( 'Ignore this step', 'secupress') . '</span>
	</a>';
	?>

	<p class="secupress-step-title"><?php echo $page_title; ?></p>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>
<?php
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
		$class_name_parts        = array_merge( $this_prio_warning_scans, $this_prio_bad_scans );
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
	<div id="secupress-tests" class="secupress-tests">
	<div class="secupress-scans-group secupress-group-<?php echo $module_name; ?>">
	<?php

	foreach ( $class_name_parts as $option_name => $class_name_part ) {
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
		++$i;

		if ( ! $is_subsite ) {
		?>
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<i class="icon-user-login" aria-hidden="true"></i>
				<p class="secupress-sgh-title"><?php echo $module_title; ?></p>
				<p class="secupress-sgh-description"><?php echo $module_summary; ?></p>
			</div>


		</div><!-- .secupress-sg-header -->
		<!-- //// geof iic ce bandeau est donc plus clair avec une dot "orange" -->
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<p class="secupress-sgh-title">&middot; <?php echo $current_test::$title; ?></p>
			</div>


		</div><!-- .secupress-sg-header -->
		<?php } ?>
		<div id="secupress-group-content-<?php echo $module_name; ?>" class="secupress-sg-content">

			<div class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all <?php echo $row_css_class; ?>" id="<?php echo $class_name_part; ?>">
				<div class="secupress-flex">

					<p class="secupress-item-title"><?php _e( '<b>How to Fix</b>', 'secupress' ); ?><br><?php echo wp_kses( $current_test::$more_fix, $allowed_tags ); ?></p>
					<p class="secupress-item-title"><?php _e( '<b>More Details</b>', 'secupress' ); ?><br><?php echo wp_kses( $current_test::$more, $allowed_tags ); ?></p>

					<?php
						$fix_actions = $current_test->get_required_fix_action_template_parts( $fix_actions );
						var_dump( $fix_actions ); //// toujours 0 :/
					?>

					<p class="secupress-row-actions">
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text">Read the documentation</span>
						</a>
						<?php if ( 'pro' !== $current_test::$fixable || secupress_is_pro() ) { ?>
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text"><?php _e( 'Ask for support', 'secupress' ); ?></span>
						</a>
						<?php } ?>
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix hide-is-no-js shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text"><?php _e( 'Ignore it', 'secupress' ); ?></span>
						</a>
						<?php if ( $is_fixable && $current_test::need_manual_fix() ) { ?>
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text"><?php _e( 'Fix it', 'secupress' ); ?></span>
						</a>
						<?php } elseif ( $is_fixable && ! $current_test::need_manual_fix() ) { ?>
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text"><?php _e( 'Retry to fix', 'secupress' ); ?></span>
						</a>
						<?php } elseif ( 'pro' === $current_test::$fixable && ! secupress_is_pro() ) { ?>
						<a href="#" class="secupress-button secupress-button-tertiary secupress-button-autofix shadow">
							<span class="icon">
								<i class="icon-cross" aria-hidden="true"></i>
							</span>
							<span class="text"><?php _e( 'Get PRO', 'secupress' ); ?></span>
						</a>
						<?php } ?>
					</p>

					<div class="secupress-item-details" id="details-<?php echo $class_name_part; ?>">
						<div class="secupress-flex">
							<span class="secupress-details-icon">
								<i class="icon-i" aria-hidden="true"></i>
							</span>
							<p class="details-content"><?php echo wp_kses( $current_test::$more, $allowed_tags ); ?></p>
							<span class="secupress-placeholder"></span>
						</div>
					</div>

				</div>

			</div><!-- .secupress-item-all -->

		</div><!-- .secupress-sg-content -->
		<?php
	}
}
?>
	</div><!-- .secupress-scans-group -->

</div><!-- .secupress-tests -->
