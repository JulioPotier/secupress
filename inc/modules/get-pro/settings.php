<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$plans = get_transient( 'secupress_pro_plans' );

/**
 * Make sure the transient doesn't contain data from the previous API.
 * It shouldn't, since the upgrader should have run, but we already had a haunted site where logic is not the rule and the mind is lost into unknown dimensions.
 * Specialists call it the Emilie effect. If it can go wrong, it will go wrong. Even if it can't.
 */
if ( ! is_array( $plans ) || empty( $plans[0]['en_US']['name'] ) ) {
	$plans = false;
}

if ( false === $plans ) {
	$response = wp_remote_get( SECUPRESS_WEB_MAIN . 'api/plugin/plans/1.0/' );

	if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
		$plans = wp_remote_retrieve_body( $response );
		$plans = json_decode( $plans, true );
		set_transient( 'secupress_pro_plans', $plans, DAY_IN_SECONDS );
	}
}

if ( ! $plans ) {
	$plans      = json_decode( '[{"en_US":{"name":"Lite","websites":1,"price":{"currency":"$","currency_pos":"before","year":"57.60"},"url":{"year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=4"}},"fr_FR":{"name":"Lite","websites":1,"price":{"currency":"$","currency_pos":"before","year":"57.60"},"url":{"year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=4"}}},{"en_US":{"name":"Standard","websites":3,"price":{"currency":"$","currency_pos":"before","year":"144"},"url":{"year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=5"}},"fr_FR":{"name":"Standard","websites":3,"price":{"currency":"$","currency_pos":"before","year":"144"},"url":{"year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=5"}}},{"en_US":{"name":"Plus","websites":10,"price":{"currency":"$","currency_pos":"before","year":"288"},"url":{"year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=6"}},"fr_FR":{"name":"Plus","websites":10,"price":{"currency":"$","currency_pos":"before","year":"288"},"url":{"year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=6"}}},{"en_US":{"name":"Unlimited","websites":-1,"price":{"currency":"$","currency_pos":"before","year":"479"},"url":{"year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=8"}},"fr_FR":{"name":"Unlimited","websites":-1,"price":{"currency":"$","currency_pos":"before","year":"479"},"url":{"year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=8"}}}]', true );
	$impossible = sprintf( '<p class="secupress-response-notice secupress-rn-warning secupress-text-center">' . __( 'Impossible to get online prices, please check %1$sonline prices%2$s to get the last ones.', 'secupress' ), '<a href="https://secupress.me/downloads/secupress/" target="_blank">', '</a>' ) . '</p>';
}
?>

	<div class="secupress-section-dark secupress-settings-header secupress-flex">
		<div class="secupress-col-1-3 secupress-col-logo secupress-text-center">
			<div class="secupress-logo-block">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => 96 ) ); ?>
				</div>
			</div>
		</div>
		<div class="secupress-col-2-3 secupress-col-text">
			<p class="secupress-text-medium"><?php esc_html_e( 'Get exclusive features to protect your website with SecuPress&#160;Pro', 'secupress' ); ?></p>
		</div>
	</div>

	<div class="secupress-section">
		<?php
		if ( isset( $impossible ) ) {
			echo $impossible;
		}
		?>

		<div id="secupress-pricing" class="secupress-pricing secupress-flex secupress-text-center">
			<?php
			$locale = get_locale();

			foreach ( $plans as $plan ) {
				$plan           = isset( $plan[ $locale ] ) ? $plan[ $locale ] : $plan['en_US'];
				$currency       = esc_html( $plan['price']['currency'] );
				$currency_after = 'before' !== $plan['price']['currency_pos'];
				// 1 is the currency symbol, 2 is the price.
				$price_template = $currency_after ? '%2$s%1$s' : '%1$s%2$s';
				?>
				<div class="secupress-col-1-4 secupress-flex">
					<div class="secupress-price secupress-box-shadow secupress-flex-col">
						<div class="secupress-price-header">
							<p class="secupress-price-name"><?php echo esc_html( $plan['name'] ); ?></p>
							<p class="secupress-amounts">
								<?php printf( $price_template, '<span class="secupress-dollars">' . $currency . '</span>', '<span class="price">' . esc_html( $plan['price']['year'] ) . '</span>' ); ?>
							</p>
						</div>
						<div class="secupress-price-details">
							<p class="secupress-pd-info"><?php _e( 'Billed per year', 'secupress' ); ?></p>
							<p class="secupress-pd-benefits">
								<?php if ( -1 < (int) $plan['websites'] ) { ?>
									<strong><?php echo esc_html( sprintf( _n( '%d Site', '%d Sites', (int) $plan['websites'], 'secupress' ), (int) $plan['websites'] ) ); ?></strong>
								<?php } else { ?>
									<strong><?php _ex( 'Unlimited Sites', 'websites', 'secupress' ); ?></strong>
								<?php } ?>
							</p>
						</div>
						<div class="secupress-price-cta">
							<a href="<?php echo esc_url( $plan['url']['year'] ); ?>" class="secupress-button secupress-button-primary shadow" target="_blank"><?php _e( 'Order', 'secupress' ); ?></a>
						</div>
					</div>
				</div>
				<?php
			}
			?>
		</div><!-- #secupress-pricing -->

		<p class="secupress-catchphrase"><?php _e( 'Included With All Plans', 'secupress' ); ?></p>

		<div class="secupress-pro-crossed-offers secupress-flex secupress-text-center secupress-p2">
			<div class="secupress-col-1-3">
				<img src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>icon-sos.png" width="66" height="66" alt="<?php esc_attr_e( 'Support', 'secupress' ); ?>">
				<p><?php _e( 'Unlimited Support and Updates', 'secupress' ); ?></p>
			</div>
			<div class="secupress-col-1-3">
				<img src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>icon-imagify.png" width="66" height="66" alt="Imagify">
				<p><?php printf( _x( 'Bonus %1$s on %2$s', 'one line text please', 'secupress' ), '<strong class="secupress-tertiary">' . __( '100 MB for free', 'secupress' ) . '</strong>', '<strong>Imagify</strong>' ); ?></p>
			</div>
			<div class="secupress-col-1-3">
				<img src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>icon-wp-rocket.png" width="66" height="66" alt="WP Rocket">
				<p><?php printf( _x( 'Bonus %1$s on %2$s', 'one line text please', 'secupress' ), '<strong class="secupress-tertiary">' . __( '20% OFF', 'secupress' ) . '</strong>', '<strong>WP&nbsp;Rocket</strong>' ); ?></p>
			</div>
		</div>

		<?php secupress_print_pro_advantages(); ?>

	</div>
