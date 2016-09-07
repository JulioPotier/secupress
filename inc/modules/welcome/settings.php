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
					<p class="secupress-lb-title">
					<?php echo secupress_get_logo_word( array( 'width' => 110, 'height' => 26 ) ); ?>
					</p>
				</div>
			</div>
		</div>
		<div class="secupress-col-2-3 secupress-col-text">
			<p class="secupress-text-medium"><?php _e( 'Secure your website deeper thanks to our dedicated modules', 'secupress' ); ?></p>
			<p><?php _e( 'Anti-Malware, Firewall, or Anti-Spam: add features, schedule scans and protect your data.', 'secupress' ); ?></p>
		</div>
	</div>

	<?php if ( ! secupress_is_pro() ) { ?>
		<div class="secupress-section-gray-dark secupress-section-mini secupress-flex">
			<div class="secupress-col-1-4 secupress-col-icon">
				<i class="icon-secupress-simple" aria-hidden="true"></i>
			</div>
			<div class="secupress-col-2-4 secupress-col-text">
				<p class="secupress-text-basup"><?php _e( 'Get a better score and unlock all features', 'secupress' ); ?></p>
			</div>
			<div class="secupress-col-1-4 secupress-col-cta">
				<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ); ?>" class="secupress-button secupress-button-tertiary">
					<?php _e( 'Get Pro', 'secupress' ); ?>
				</a>
			</div>
		</div><!-- .secupress-section-medium -->
	<?php } ?>

	<div class="secupress-modules-dashboard secupress-bordered secupress-flex secupress-wrap">
		<?php
		$modules = $this->get_modules();
		$pro_msg = '<span class="secupress-cta-pro">' . static::get_pro_version_string() . '</span>';

		// Do not display the get pro block, but we still need it for the content.
		unset( $modules['get-pro'] );

		foreach ( $modules as $slug => $mod ) {
			?>
			<div class="secupress-module-box secupress-flex-col secupress-module-box-<?php echo sanitize_key( $slug ); ?>">
				<p class="secupress-mb-title"><?php echo $mod['title'] ?></p>
				<p class="secupress-mb-description"><?php echo $mod['summaries']['normal']; ?></p>
				<p class="secupress-mb-action">
					<a href="<?php echo esc_url( secupress_admin_url( 'modules', $slug ) ); ?>" class="secupress-button-primary">
						<?php _e( 'View options', 'secupress' ); ?>
					</a>
					<?php echo ! empty( $mod['mark_as_pro'] ) ? $pro_msg : ''; ?>
				</p>
				<i class="icon-<?php echo $mod['icon']; ?>" aria-hidden="true"></i>
			</div>
			<?php
		} // End foreach $modules.
		?>
	</div>
