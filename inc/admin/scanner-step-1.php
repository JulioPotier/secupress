<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$scanned_items          = get_option( SECUPRESS_SCAN_SLUG );
$scanned_items          = is_array( $scanned_items ) ? array_flip( array_keys( $scanned_items ) ) : array();
$secupress_tests_keys   = array_flip( array_map( 'strtolower', call_user_func_array( 'array_merge', $secupress_tests ) ) );
$new_scans              = array_diff_key( $secupress_tests_keys, $scanned_items );
$is_there_something_new = false !== reset( $new_scans );
$modules                = secupress_get_modules();

//// new items not working yet.
foreach ( $secupress_tests as $module_name => $class_name_parts ) {
	$i = 0;

	$module_title     = ! empty( $modules[ $module_name ]['title'] )              ? $modules[ $module_name ]['title']              : '';
	$module_summary   = ! empty( $modules[ $module_name ]['summaries']['small'] ) ? $modules[ $module_name ]['summaries']['small'] : '';
	$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
	$this_new_scans   = array_diff_key( $class_name_parts, $new_scans );

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

	if ( 0 !== $is_there_something_new ) {
	?>
	<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">

		<?php
		$page_title = $is_there_something_new ? sprintf( __( 'There\'re new exciting things in %s! You\'ll need to re-scan your website', 'secupress' ), SECUPRESS_PLUGIN_NAME ) : __( 'List of security points to analyze', 'secupress' );

		if ( $is_there_something_new ) {
			$main_button =
			'<button class="secupress-button secupress-button-primary button-secupress-scan shadow" type="button" data-nonce="' . esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ) . '">
				<span class="icon" aria-hidden="true">
					<i class="icon-radar"></i>
				</span>
				<span class="text">' . esc_html__( 'Re-scan website', 'secupress' ) . '</span>
			</button>';
		} else {
			$main_button =
			'<a href="' . secupress_admin_url( 'scanners' ) . '&step=2" class="secupress-button secupress-button-tertiary shadow">
				<span class="icon">
					<i class="icon-wrench" aria-hidden="true"></i>
				</span>
				<span class="text">' . esc_html__( 'Next step', 'secupress') . '</span>
			</a>';
		}
		?>

		<p class="secupress-step-title"><?php echo $page_title; ?></p>
		<p>
			<?php echo $main_button; ?>
		</p>
	</div>

	<div id="secupress-tests" class="secupress-tests">
	<?php
	}

		$is_there_something_new = 0; // this will prevent to show up during the next foreach iteration //// put this under the if
	if ( false /*$is_there_something_new*/ ) {
	?>
	<div class="secupress-scans-group secupress-group-new">
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<i class="icon-secupress-simple" aria-hidden="true"></i>
				<p class="secupress-sgh-title"><?php printf( esc_html__( '%sNew Items', 'secupress' ), ( SECUPRESS_PLUGIN_NAME === 'SecuPress' ? SECUPRESS_PLUGIN_NAME . ' ' . SECUPRESS_VERSION . ' ' : '' ) ); ?></p>
				<p class="secupress-sgh-description"><?php _e( 'These new points have to be scanned now.', 'secupress' ); ?></p>
			</div>

			<div class="secupress-sgh-actions secupress-flex">
				<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-new">
					<i class="icon-angle-up" aria-hidden="true"></i>
					<span class="screen-reader-text"><?php _e( 'Show/hide panel', 'secupress' ); ?></span>
				</button>
			</div>

		</div><!-- .secupress-sg-header -->

		<div id="secupress-group-content-new" class="secupress-sg-content">

		<?php
		foreach ( $this_new_scans as $option_name => $class_name_part ) {
			++$i;
			$class_name   = 'SecuPress_Scan_' . $class_name_part;
			$current_test = $class_name::get_instance();
			$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners' . ( $is_subsite ? '' : '#' . $class_name_part ) ) ) );
			$is_fixable   = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();

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
			$row_css_class  = ' status-' . sanitize_html_class( $scan_status );
			$row_css_class .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
			$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
			$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
			$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';

		?>
			<div class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all type-wordpress status-new not-fixable no-fix-status" id="<?php echo $class_name_part; ?>">
				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label"><?php _ex( 'New', 'scan status', 'secupress' ); ?></span>
					</p>

					<p class="secupress-item-title"><?php echo $class_name->title; ?></p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-<?php echo $class_name_part; ?>" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text"><?php _e( 'Learn more', 'secupress' ); ?></span>
						</button>
					</p>
				</div>

				<div class="secupress-item-details hide-if-js" id="details-<?php echo $class_name_part; ?>">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content"><?php echo wp_kses( $current_test->more, $allowed_tags ); ?></p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->
		<?php } ?>
		</div><!-- .secupress-sg-content -->
	</div><!-- .secupress-scans-group -->
	<?php
	} // is something new in that version

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
				<a href="<?php echo secupress_admin_url( 'modules' ) . '&module=' . $module_name; ?>" target="_blank" class="secupress-link-icon secupress-vcenter">
					<span class="icon"><i class="icon-cog" aria-hidden="true"></i></span>
					<span class="text"><?php _e( 'Go to module settings', 'secupress' ); ?></span>
				</a>
				<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-<?php echo $module_name; ?>">
					<i class="icon-angle-up" aria-hidden="true"></i>
					<span class="screen-reader-text"><?php _e( 'Show/hide panel', 'secupress' ); ?></span>
				</button>
			</div>

		</div><!-- .secupress-sg-header -->
	<?php
	}

	foreach ( $class_name_parts as $option_name => $class_name_part ) {
		++$i;
		$class_name   = 'SecuPress_Scan_' . $class_name_part;
		$current_test = $class_name::get_instance();
		$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners' . ( $is_subsite ? '' : '#' . $class_name_part ) ) ) );
		$is_fixable   = true === $current_test->is_fixable() || 'pro' === $current_test->is_fixable() && secupress_is_pro();

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
		$row_css_class  = ' status-' . sanitize_html_class( $scan_status );
		$row_css_class .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
		$row_css_class .= $is_fixable ? ' fixable' : ' not-fixable';
		$row_css_class .= ! empty( $fix['has_action'] ) ? ' status-hasaction' : '';
		$row_css_class .= ! empty( $fix['status'] ) && empty( $fix['has_action'] ) ? ' has-fix-status' : ' no-fix-status';

		?>
		<div id="secupress-group-content-<?php echo $module_name; ?>" class="secupress-sg-content">

			<div class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all <?php echo $row_css_class; ?>" id="<?php echo $class_name_part; ?>">
				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label"><?php echo secupress_status( $scan_status ); ?></span>
					</p>

					<p class="secupress-item-title"><?php echo $scan_message; ?></p>

					<p class="secupress-row-actions">
						<a class="secupress-button secupress-button-mini secupress-scanit hide-if-js" href="<?php echo esc_url( $scan_nonce_url ); ?>">
							<span class="icon" aria-hidden="true">
								<i class="icon-refresh"></i>
							</span>
							<span class="text">
								<?php echo 'notscannedyet' === $scan_status ? _x( 'Scan', 'verb', 'secupress' ) : _x( 'Re-Scan', 'verb', 'secupress' ); ?>
							</span>
						</a><br class="hide-if-js"/>
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-<?php echo $class_name_part; ?>" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text"><?php _e( 'Learn more', 'secupress' ); ?></span>
						</button>
					</p>
				</div>

				<div class="secupress-item-details hide-if-js" id="details-<?php echo $class_name_part; ?>">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content"><?php echo wp_kses( $current_test->more, $allowed_tags ); ?></p>
						<span class="secupress-placeholder"></span>
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
		if ( !secupress_is_pro() ) {
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
	<p>
		<?php echo $main_button; ?>
	</p>
</div>
