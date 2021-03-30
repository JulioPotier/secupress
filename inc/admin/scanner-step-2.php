<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Keep only scans with "bad" status.
$this_step_scans  = $bad_scans;	// `array( $class_name_part_lower => $status )`
$fixable_modules  = array();	// Will tell which modules have fixable items.
$secupress_is_pro = secupress_is_pro();

// Keep only scans that are fixable automatically + require the scan files.
foreach ( $secupress_tests as $module_name => $class_name_parts ) {

	$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
	$class_name_parts = array_intersect_key( $class_name_parts, $this_step_scans );

	// Only those with "bad" status.
	if ( ! $class_name_parts ) {
		unset( $secupress_tests[ $module_name ] );
		continue;
	}

	$secupress_tests[ $module_name ] = $class_name_parts;
	$fixable_modules[ $module_name ] = false;

	foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) {
		if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ] );
			continue;
		}

		secupress_require_class( 'scan', $class_name_part );
		$class_name       = 'SecuPress_Scan_' . $class_name_part;
		$current_test     = $class_name::get_instance();
		$is_fixable       = $current_test->is_fixable();

		// Remove those that are not fixable automatically.
		if ( false === $is_fixable ) {
			unset( $secupress_tests[ $module_name ][ $class_name_part_lower ] );
		}
		// Tell if the module has fixable items.
		elseif ( ! $fixable_modules[ $module_name ] && ( true === $is_fixable || 'pro' === $is_fixable && $secupress_is_pro ) ) {
			$fixable_modules[ $module_name ] = true;
		}
	}
}

$secupress_tests = array_filter( $secupress_tests );

// Move along, move along...
if ( ! $secupress_tests ) {
	?>
	<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
		<p class="secupress-step-title"><?php _e( 'Nothing to do here', 'secupress' ); ?></p>
		<p class="secupress-flex">
			<a href="<?php echo esc_url( secupress_admin_url( 'scanners' ) ); ?>&amp;step=3" class="secupress-button shadow light">
				<span class="icon">
					<i class="secupress-icon-cross" aria-hidden="true"></i>
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
	$has_fixes   = (bool) array_filter( $fixable_modules );
	if ( $secupress_is_pro ) {
		$main_button =
		'<button class="secupress-button secupress-button-tertiary secupress-button-autofix shadow' . ( $has_fixes ? '' : ' hidden' ) . '" type="button">
			<span class="icon">
				<i class="secupress-icon-wrench" aria-hidden="true"></i>
			</span>
			<span class="text">' . __( 'Fix it', 'secupress' ) . '</span>
		</button>';
	} else {
		$main_button =
		'
		<a href="' . esc_url( secupress_admin_url( 'scanners' ) ) . '&amp;step=3" class="secupress-button secupress-button-tertiary shadow">
			<span class="icon">
				<i class="secupress-icon-wrench" aria-hidden="true"></i>
			</span>
			<span class="text">' . __( 'Next step', 'secupress' ) . '</span>
		</a>';
	}
	$main_button .=
		'<a href="' . esc_url( secupress_admin_url( 'scanners' ) ) . '&amp;step=3" class="secupress-button shadow light' . ( $has_fixes ? ' hidden' : '' ) . '">
			<span class="icon">
				<i class="secupress-icon-cross" aria-hidden="true"></i>
			</span>
			<span class="text">' . __( 'Ignore this step', 'secupress' ) . '</span>
		</a>';
	if ( ! $secupress_is_pro ) {
	?>
	<span><?php // Flex col placeholder. ?></span>
	<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
		<p class="secupress-step-title"> </p>
		<p class="secupress-flex">
			<a href="<?php echo esc_url( secupress_admin_url( 'scanners' ) ); ?>&amp;step=3" class="secupress-button secupress-button-tertiary shadow">
				<span class="icon">
					<i class="secupress-icon-wrench" aria-hidden="true"></i>
				</span>
				<span class="text"><?php _e( 'Next step', 'secupress' ); ?></span>
			</a>
		</p>
	</div>
	<?php
	} else {
	?>
	<p class="secupress-step-title"><?php _e( 'Only checked items will be automatically fixed', 'secupress' ); ?></p>
	<p>
		<?php echo $main_button; ?>
	</p>
<?php } ?>
</div>

<div id="secupress-tests" class="secupress-tests">
	<?php
	$modules = secupress_get_modules();

	foreach ( $secupress_tests as $module_name => $class_name_parts ) {

		$module_icon    = ! empty( $modules[ $module_name ]['icon'] )               ? $modules[ $module_name ]['icon']               : '';
		$module_title   = ! empty( $modules[ $module_name ]['title'] )              ? $modules[ $module_name ]['title']              : '';
		$module_summary = ! empty( $modules[ $module_name ]['summaries']['small'] ) ? $modules[ $module_name ]['summaries']['small'] : '';
		?>
		<div class="secupress-scans-group secupress-group-<?php echo $module_name; ?>">
			<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

				<div class="secupress-sgh-name">
					<i class="secupress-icon-<?php echo $module_icon; ?>" aria-hidden="true"></i>
					<p class="secupress-sgh-title"><?php echo $module_title; ?></p>
					<p class="secupress-sgh-description"><?php echo $module_summary; ?></p>
				</div>

				<div class="secupress-sgh-actions secupress-flex">
					<?php if ( $fixable_modules[ $module_name ] && $secupress_is_pro ) : ?>
						<label class="text hide-if-no-js" for="secupress-toggle-check-<?php echo $module_name; ?>">
							<span class="label-before-text"><?php _e( 'Toggle group check', 'secupress' ); ?></span>
							<input type="checkbox" id="secupress-toggle-check-<?php echo $module_name; ?>" class="secupress-checkbox secupress-toggle-check" checked="checked"/>
							<span class="label-text"></span>
						</label>
					<?php endif; ?>
				</div>

			</div><!-- .secupress-sg-header -->

			<?php if ( ! secupress_is_pro() ) { ?>
			<div class="secupress-get-pro-version-div">
				<span class="secupress-get-pro-version">
					<?php printf( __( 'The <a href="%s" target="_blank">Pro Version</a> is required to autofix issues, fix it manually on next step.', 'secupress' ), esc_url( secupress_admin_url( 'get-pro' ) ) ); ?>
				</span>
			</div>
			<?php } ?>

			<div id="secupress-group-content-<?php echo $module_name; ?>" class="secupress-sg-content">
				<?php
				foreach ( $class_name_parts as $class_name_part_lower => $class_name_part ) {
					$class_name   = 'SecuPress_Scan_' . $class_name_part;
					$current_test = $class_name::get_instance();
					$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners&step=2#' . $class_name_part ) ) );
					$needs_pro    = 'pro' === $current_test->is_fixable() && ! $secupress_is_pro;

					// Scan.
					$scanner        = isset( $scanners[ $class_name_part_lower ] ) ? $scanners[ $class_name_part_lower ] : array();
					$scan_status    = ! empty( $scanner['status'] ) ? $scanner['status'] : 'notscannedyet';
					$scan_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_scanner_' . $class_name_part );

					// Fix.
					$fix           = ! empty( $fixes[ $class_name_part_lower ] ) ? $fixes[ $class_name_part_lower ] : array();
					$fix_nonce_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer ), 'secupress_fixit_' . $class_name_part );

					// Row css class.
					$row_css_class  = 'secupress-item-' . $class_name_part;
					$row_css_class .= ' status-' . sanitize_html_class( $scan_status );
					$row_css_class .= $needs_pro ? ' secupress-only-pro not-fixable' : '';
					$row_css_class .= ! secupress_is_pro() ? ' disabled' : '';
					?>
					<div class="secupress-item-all <?php echo $row_css_class; ?>" id="<?php echo $class_name_part; ?>" data-scan-url="<?php echo esc_url( $scan_nonce_url ); ?>">
						<div class="secupress-flex">

							<p class="secupress-item-status secupress-status-mini">
								<span class="secupress-dot-bad"></span>
							</p>

							<p class="secupress-item-title"><?php echo wp_kses( $current_test->more_fix, $allowed_tags ); ?></p>

							<p class="secupress-row-actions">
								<?php
								if ( $needs_pro ) {
									// It is fixable with the pro version but the free version is used.
									?>
									<span class="secupress-get-pro-version">
										<?php printf( __( 'This feature and its fix are available in <a href="%s" target="_blank">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get-pro' ) ) ); ?>
									</span>
									<?php
								} else {
									// It can be fixed.
									if ( $secupress_is_pro ) {
									?>
									<input type="checkbox" id="secupress-item-<?php echo $class_name_part; ?>" class="secupress-checkbox secupress-row-check hide-if-no-js" checked="checked"/>
									<?php } ?>
									<label for="secupress-item-<?php echo $class_name_part; ?>" class="label-text hide-if-no-js">
										<span class="screen-reader-text"><?php _e( 'Auto-fix this item', 'secupress' ); ?></span>
									</label>
									<a class="secupress-button-primary secupress-button-mini hide-if-js secupress-fixit<?php echo $current_test->is_delayed_fix() ? ' delayed-fix' : ''; ?>" href="<?php echo esc_url( $fix_nonce_url ); ?>">
										<span class="icon" aria-hidden="true">
											<i class="secupress-icon-shield"></i>
										</span>
										<span class="text">
											<?php _e( 'Fix it', 'secupress' ); ?>
										</span>
									</a>
									<?php
								}
								?>
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
</div><!-- .secupress-tests -->

<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced">
	<span><?php // Flex col placeholder. ?></span>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>

<div id="secupress-spinner" class="secupress-scans-group secupress-group-spinner hidden" aria-hidden="true">
	<div class="secupress-sg-header">
		<div class="secupress-sgh-name">
			<p class="secupress-sgh-title"><?php esc_html_e( 'Currently fixing&hellip;', 'secupress' ); ?></p>
			<p class="secupress-sgh-description"><?php esc_html_e( 'Please grab a cup of water, open a book and just wait a few minutes.', 'secupress' ); ?></p>
		</div>
	</div>
	<div class="secupress-spinner-content secupress-text-center secupress-p3">

		<img class="secupress-big-spinner secupress-mb1" src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>spinner-big.png" srcset="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>spinner-big2x.png 2x" alt="<?php esc_attr_e( 'Fixing…', 'secupress' ); ?>" width="128" height="128">

		<p class="secupress-text-basup"><?php _e( 'You’ll be automatically redirected to the next step,<br>if you are not within 5 minutes, please reload the page or ignore this step.', 'secupress' ); ?></p>

	</div>
</div>
