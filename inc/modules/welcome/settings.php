<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
?>

	<h2><?php esc_html_e( 'Welcome in your modules dashboard.', 'secupress' ); ?></h2>
	
	<div class="secupress-modules-dashboard secupress-bordered secupress-flex secupress-wrap">
		<?php
			$modules = $this->get_modules();

			foreach ( $modules as $slug => $mod ) {
		?>
			<div class="secupress-module-box secupress-flex-col secupress-module-box-<?php echo sanitize_key( $slug ); ?>">
				<p class="secupress-mb-title"><?php echo $mod['title'] ?></p>
				<p class="secupress-mb-description"><?php echo $mod['description'][0]; ?></p>
				<p class="secupress-mb-action">
					<a href="<?php echo esc_url( secupress_admin_url( 'modules', $slug ) ); ?>" class="secupress-button-primary">
						<?php esc_html_e( 'View options', 'secupress' ); ?>
					</a>
				</p>
				<i class="dashicons dashicons-<?php echo $mod['dashicon']; ?>" aria-hidden="true"></i>
			</div>
		<?php
			} // end foreach $modules
		?>
	</div>
