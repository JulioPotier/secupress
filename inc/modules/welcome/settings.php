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
			<p class="secupress-text-medium"><?php esc_html_e( 'Secure your website with to our dedicated modules', 'secupress' ); ?></p>
			<p><?php esc_html_e( 'Anti-Malware, Firewall, or Anti-Spam: add features, schedule scans and protect your data.', 'secupress' ); ?></p>
		</div>
	</div>

	<div class="secupress-modules-dashboard secupress-bordered secupress-section-gray">
		<div class="secupress-modules-container secupress-box-shadow">

		<?php
		$modules  = SecuPress_Settings_Modules::get_modules();
		$pro_msg  = '<span class="secupress-cta-pro">' . SecuPress_Settings_Modules::get_pro_version_string() . '</span>';
		$pro_info = 0;

		foreach ( $modules as $slug => $mod ) {
			$pro_info     = ! empty( $mod['mark_as_pro'] )            ? $pro_info + 1                  : $pro_info;
			$free_options = ! empty( $mod['counts']['free_options'] ) ? $mod['counts']['free_options'] : 0;
			$av_options   = ! empty( $mod['mark_as_pro'] )            ? _n( '%d free option available', '%d free options available', $free_options,  'secupress' ) : _n( '%d option available', '%d options available', $free_options, 'secupress' );
			$nb_options   = ! empty( $mod['counts']['free_options'] ) ? '<span class="secupress-mb-title-datas"><i class="secupress-icon-info-disk secupress-primary" aria-hidden="true"></i>' . sprintf( $av_options, $mod['counts']['free_options'] ) . '</span>' : '';

			if ( 1 === $pro_info ) {
			?>
			<div class="secupress-module-box secupress-flex secupress-module-box-get-pro">
				<div class="secupress-mb-icon">
					<i class="secupress-icon-secupress-simple" aria-hidden="true"></i>
				</div>
				<div class="secupress-mb-texts">
					<p class="secupress-mb-title"><?php _e( 'Get Pro and unlock more awesome features!', 'secupress' ); ?></p>
					<p class="secupress-mb-description"><?php _e( 'Explore the modules and unlock the Pro options, and because we’re nice, you have plenty of free options too!', 'secupress' ); ?></p>
				</div>
				<p class="secupress-mb-action">
					<a href="<?php echo esc_url( secupress_admin_url( 'modules', $slug ) ); ?>" class="secupress-button-tertiary">
						<span class="icon">
							<i class="secupress-icon-secupress-simple" aria-hidden="true"></i>
						</span>
						<span class="text"><?php _e( 'Get Pro', 'secupress' ); ?></span>
					</a>
				</p>
			</div>
			<?php
			} // if first time we get a pro line, display info about pro before
			?>
			<div class="secupress-module-box secupress-flex secupress-module-box-<?php echo sanitize_key( $slug ); ?>">
				<div class="secupress-mb-icon">
					<i class="secupress-icon-<?php echo $mod['icon']; ?>" aria-hidden="true"></i>
				</div>
				<div class="secupress-mb-texts">
					<p class="secupress-mb-title">
						<span class="secupress-mb-title-text"><?php echo $mod['title'] ?></span>
					</p>
					<p class="secupress-mb-description"><?php echo $mod['summaries']['normal']; ?></p>
				</div>
				<p class="secupress-mb-available-pro">
					<?php echo ! empty( $mod['mark_as_pro'] ) ? $pro_msg : ''; ?>
				</p>
				<p class="secupress-mb-action">
					<a href="<?php echo esc_url( secupress_admin_url( 'modules', $slug ) ); ?>" class="secupress-button-primary">
						<?php _e( 'View options', 'secupress' ); ?>
					</a>
				</p>
			</div>
			<?php
		} // End foreach $modules.
		?>
		</div><!-- .secupress-modules-container -->
	</div><!-- .secupress-modules-dashboard -->
