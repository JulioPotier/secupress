<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$scanned_items          = get_option( SECUPRESS_SCAN_SLUG );
$scanned_items          = is_array( $scanned_items ) ? array_flip( array_keys( $scanned_items ) ) : array();
$secupress_tests_keys   = array_flip( array_map( 'strtolower', call_user_func_array( 'array_merge', $secupress_tests ) ) );
$new_scans              = array_diff_key( $secupress_tests_keys, $scanned_items );
$modules                = secupress_get_modules();
$is_there_something_new = false !== reset( $new_scans );
$flag_first_iteration   = true;
?>

<div id="secupress-tests" class="secupress-tests">
	<?php
	foreach ( $secupress_tests as $module_name => $class_name_parts ) {
		$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );
		$this_new_scans   = array_intersect_key( $class_name_parts, $new_scans );

		if ( ! $is_subsite ) {
			foreach ( $class_name_parts as $option_name => $class_name_part ) {
				if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
					unset( $class_name_parts[ $option_name ] );
					continue;
				}

				secupress_require_class( 'scan', $class_name_part );
			}

			// For this module, order the scans by status: 'good', 'warning', 'bad', 'new'.
			$this_module_good_scans    = array_intersect_key( $class_name_parts, $good_scans );
			$this_module_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
			$this_module_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
			$class_name_parts          = array_merge( $this_new_scans, $this_module_good_scans, $this_module_warning_scans, $this_module_bad_scans );
			unset( $this_module_bad_scans, $this_module_warning_scans, $this_module_good_scans );
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

		$class_name_parts = array_diff_key( $class_name_parts, $new_scans );

		if ( $is_there_something_new ) {
			$_class_name_parts      = $class_name_parts;
			$class_name_parts       = $this_new_scans;
		}

		if ( $flag_first_iteration ) {
		?>
			<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">
				<?php
				if ( $is_there_something_new && $scanned_items ) {
					$page_title  = sprintf( __( 'There are new exciting things in %s! You\'ll need to re-scan your website', 'secupress' ), SECUPRESS_PLUGIN_NAME );
					$main_button =
					'<button class="secupress-button secupress-button-primary button-secupress-scan shadow" type="button" data-nonce="' . esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ) . '">
						<span class="icon" aria-hidden="true">
							<i class="icon-radar"></i>
						</span>
						<span class="text">' . __( 'Re-scan website', 'secupress' ) . '</span>
					</button>';
				} else {
					$page_title  = __( 'List of security points to analyze', 'secupress' );
					$main_button =
					'<a href="' . secupress_admin_url( 'scanners' ) . '&step=2" class="secupress-button secupress-button-tertiary shadow">
						<span class="icon">
							<i class="icon-wrench" aria-hidden="true"></i>
						</span>
						<span class="text">' . __( 'Next step', 'secupress') . '</span>
					</a>';
				}
				?>
				<p class="secupress-step-title">
					<?php echo $page_title; ?>
				</p>
				<p>
					<?php echo $main_button; ?>
				</p>
			</div><!-- .secupress-step-content-header -->
		<?php
		}
		// for ($i=0; $i < 2; $i++) {
		// 	if ( 1 === $i && isset( $_class_name_parts ) ) {
		// 		$class_name_parts       = $_class_name_parts;
		// 	}
		if ( $is_there_something_new && $scanned_items ) {
			require( SECUPRESS_INC_PATH . 'admin/scanner-step-1-new.php' );
		}
		require( SECUPRESS_INC_PATH . 'admin/scanner-step-1-all.php' );
		// } // Eo for $i
	} // Eo foreach $secupress_tests
	?>
		</div><!-- .secupress-sg-content -->
	</div> <!-- .secupress-group-new -->
</div><!-- .secupress-tests -->

<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced">
	<p>
		<?php if ( secupress_is_pro() ) : ?>
			<button type="button" title="<?php esc_attr_e( 'Export this report as PDF file.', 'secupress' ); ?>" class="secupress-button shadow">
				<span class="icon">
					<i class="icon-file-pdf-o" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Export as PDF', 'secupress' ); ?>
				</span>
			</button>
		<?php else : ?>
			<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ) ?>" title="<?php esc_attr_e( 'Get the Pro Version to export this report as PDF file.', 'secupress' ); ?>" target="_blank" class="secupress-button disabled shadow">
				<span class="icon">
					<i class="icon-file-pdf-o" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Export as PDF', 'secupress' ); ?>
				</span>
			</a>
			<br>
			<span class="secupress-get-pro-version">
				<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
			</span>
		<?php endif; ?>
	</p>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>
