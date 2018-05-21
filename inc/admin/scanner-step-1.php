<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$scanned_items          = secupress_get_scan_results();
$scanned_items          = $scanned_items ? array_flip( array_keys( $scanned_items ) ) : array();
$secupress_tests_keys   = array_flip( array_map( 'strtolower', call_user_func_array( 'array_merge', $secupress_tests ) ) );
$new_scans              = array_diff_key( $secupress_tests_keys, $scanned_items );
$modules                = secupress_get_modules();
$is_there_something_new = $new_scans ? reset( $new_scans ) !== false : false;
$flag_first_iteration   = true;

// Build the "new scans" array.
if ( $new_scans ) {
	foreach ( $new_scans as $key => $new_scan ) {
		$new_scans[ $key ] = str_replace( ' ', '_', ucwords( str_replace( '_', ' ', $key ) ) );
	}
}
?>

<div id="secupress-tests" class="secupress-tests">
	<?php
	foreach ( $secupress_tests as $module_name => $class_name_parts ) {
		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );

		if ( ! $is_subsite ) {
			foreach ( $class_name_parts as $option_name => $class_name_part ) {
				if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
					unset( $class_name_parts[ $option_name ] );
					continue;
				}

				secupress_require_class( 'scan', $class_name_part );
			}

			if ( $scanned_items ) {
				// For this module, order the scans by status: 'good', 'warning', 'bad', 'new'.
				$this_module_good_scans    = array_intersect_key( $class_name_parts, $good_scans );
				$this_module_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
				$this_module_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
				$class_name_parts          = array_merge( $this_module_good_scans, $this_module_warning_scans, $this_module_bad_scans );
				unset( $this_module_bad_scans, $this_module_warning_scans, $this_module_good_scans );
			}
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

		if ( $flag_first_iteration ) {
			?>
			<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
				<?php
				if ( $is_there_something_new && $scanned_items ) {
					$page_title  = sprintf( __( 'Update %s: Discover the new security items to check', 'secupress' ), SECUPRESS_VERSION );
				} else {
					$page_title  = __( 'List of the security items already analyzed', 'secupress' );
				}
				?>
				<p class="secupress-step-title">
					<?php echo $page_title; ?>
				</p>
				<p>
					<a href="<?php echo secupress_admin_url( 'scanners' ); ?>&step=2" class="secupress-button secupress-button-tertiary shadow">
						<span class="icon">
							<i class="secupress-icon-wrench" aria-hidden="true"></i>
						</span>
						<span class="text"><?php _e( 'Next step', 'secupress' ); ?></span>
					</a>
				</p>
			</div><!-- .secupress-step-content-header -->
			<?php
			if ( $is_there_something_new && $scanned_items ) {
				require_once( SECUPRESS_INC_PATH . 'admin/scanner-step-1-new.php' );
			}
		}

		$is_there_something_new = false;

		require( SECUPRESS_INC_PATH . 'admin/scanner-step-1-all.php' );

		$flag_first_iteration = false;
	} // Eo foreach $secupress_tests.
	?>
</div><!-- .secupress-tests -->

<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced" id="secupress-step-content-footer">
	<p>
		<?php if ( secupress_is_pro() ) { ?>
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export_pdf' ), 'secupress_export_pdf' ) ); ?>" title="<?php esc_attr_e( 'Export this report as PDF file.', 'secupress' ); ?>" class="secupress-button shadow">
				<span class="icon">
					<i class="secupress-icon-file-pdf-o" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Export as PDF', 'secupress' ); ?>
				</span>
			</a>
		<?php } else { ?>
			<a href="<?php echo esc_url( secupress_admin_url( 'get-pro' ) ) ?>" title="<?php esc_attr_e( 'Get the Pro Version to export this report as PDF file.', 'secupress' ); ?>" target="_blank" class="secupress-button disabled shadow">
				<span class="icon">
					<i class="secupress-icon-file-pdf-o" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Export as PDF', 'secupress' ); ?>
				</span>
			</a>
			<br>
			<span class="secupress-get-pro-version">
				<?php printf( __( 'Available in <a href="%s" target="_blank">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get-pro' ) ) ); ?>
			</span>
		<?php } ?>
	</p>
	<p>
		<a href="<?php echo secupress_admin_url( 'scanners' ); ?>&step=2" class="secupress-button secupress-button-tertiary shadow">
			<span class="icon">
				<i class="secupress-icon-wrench" aria-hidden="true"></i>
			</span>
			<span class="text"><?php _e( 'Next step', 'secupress' ); ?></span>
		</a>
	</p>
</div>
