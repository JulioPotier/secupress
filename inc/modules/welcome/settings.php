<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
?>

	<div class="secupress-section-dark secupress-settings-header secupress-flex">
		<div class="secupress-col-1-3 secupress-col-logo secupress-text-center">
			<div class="secupress-logo-block secupress-flex">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => 131 ) ); ?>
				</div>
				<div class="secupress-lb-name">
					<p class="secupress-lb-title"><?php echo SECUPRESS_PLUGIN_NAME; ?></p>
				</div>
			</div>
		</div>
		<div class="secupress-col-2-3 secupress-col-text">
			<p class="secupress-text-medium"><?php esc_html_e( 'Securize your website deeper thanks to our modules', 'secupress' ); ?></p>
			<p><?php esc_html_e( 'Anti-Malware, Firewall, or Anti-Spam: add features, schedule scans and  save your datas.', 'secupress' ); ?></p>
		</div>
	</div>
	<?php if ( ! secupress_is_pro() ) { ?>
	<div class="secupress-section-gray-dark secupress-section-mini secupress-flex">
		<div class="secupress-col-1-4 secupress-col-icon">
			<i class="icon-secupress-simple" aria-hidden="true"></i>
		</div>
		<div class="secupress-col-2-4 secupress-col-text">
			<p class="secupress-text-basup"><?php printf( __( 'Get %s Pro and Unlock all the features and modules like: Schedules, Alerts, Firewall, Logs…', 'secupress' ), SECUPRESS_PLUGIN_NAME ); ?></p>
		</div>
		<div class="secupress-col-1-4 secupress-col-cta">
			<a href="<?php echo esc_url( secupress_admin_url( 'settings' ) ); ?>" class="secupress-button secupress-button-tertiary button-secupress-get-api-key">
				<?php _e( 'Get Pro', 'secupress' ); ?>
			</a>
		</div>
	</div><!-- .secupress-section-medium -->
	<?php }	?>
	<div class="secupress-modules-dashboard secupress-bordered secupress-flex secupress-wrap">
		<?php
		$modules = $this->get_modules();
		foreach ( $modules as $slug => $mod ) {
			?>
			<div class="secupress-module-box secupress-flex-col secupress-module-box-<?php echo sanitize_key( $slug ); ?>">
				<p class="secupress-mb-title"><?php echo $mod['title'] ?></p>
				<p class="secupress-mb-description"><?php echo $mod['summaries']['normal']; ?></p>
				<p class="secupress-mb-action">
					<a href="<?php echo esc_url( secupress_admin_url( 'modules', $slug ) ); ?>" class="secupress-button-primary">
						<?php esc_html_e( 'View options', 'secupress' ); ?>
					</a>
				</p>
				<i class="icon-<?php echo $mod['icon']; ?>" aria-hidden="true"></i>
			</div>
			<?php
		} // End foreach $modules.
		?>
	</div>
