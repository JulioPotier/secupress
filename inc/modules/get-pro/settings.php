<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$plans = get_transient( 'secupress_pro_plans' );

if ( false === $plans ) {
	$response = wp_remote_get( SECUPRESS_WEB_MAIN . 'api/plugin/plans/1.0/' );

	if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
		$plans = wp_remote_retrieve_body( $response );
		$plans = json_decode( $plans, true );
		set_transient( 'secupress_pro_plans', $plans, DAY_IN_SECONDS );
	}
}

if ( ! $plans ) {
	$plans      = json_decode( '[{"en_US":{"name":"Lite","websites":1,"price":{"currency":"$","currency_pos":"before","month":"5.99","year":"57.60","year_old":"72","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=1","year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=4"}},"fr_FR":{"name":"Lite","websites":1,"price":{"currency":"$","currency_pos":"before","month":"5.99","year":"57.60","year_old":"72","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=1","year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=4"}}},{"en_US":{"name":"Standard","websites":3,"price":{"currency":"$","currency_pos":"before","month":"14.99","year":"144","year_old":"180","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=2","year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=5"}},"fr_FR":{"name":"Standard","websites":3,"price":{"currency":"$","currency_pos":"before","month":"14.99","year":"144","year_old":"180","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=2","year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=5"}}},{"en_US":{"name":"Plus","websites":10,"price":{"currency":"$","currency_pos":"before","month":"29.99","year":"288","year_old":"360","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=3","year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=6"}},"fr_FR":{"name":"Plus","websites":10,"price":{"currency":"$","currency_pos":"before","month":"29.99","year":"288","year_old":"360","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=3","year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=6"}}},{"en_US":{"name":"Unlimited","websites":-1,"price":{"currency":"$","currency_pos":"before","month":"49.99","year":"479","year_old":"600","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=7","year":"https:\/\/secupress.me\/checkout\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=8"}},"fr_FR":{"name":"Unlimited","websites":-1,"price":{"currency":"$","currency_pos":"before","month":"49.99","year":"479","year_old":"600","drop_percent":20},"url":{"month":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=7","year":"https:\/\/secupress.me\/fr\/commande\/?edd_action=add_to_cart&download_id=14&edd_options[price_id]=8"}}}]', true );
	$impossible = sprintf( '<p class="secupress-response-notice secupress-rn-warning secupress-text-center">' . __( 'Impossible to get online prices, please check %1$sonline prices%2$s to get the last ones.', 'secupress' ), '<a href="https://secupress.me/downloads/secupress/" target="_blank">', '</a>' ) . '</p>';
}

/**
 * Check if the Pro discount is the same for all plans (same value and same type).
 * If they are, we can display a global tip next to the Yearly tab.
 */
$drop_value = null;
$drop_type  = null;
$locale     = get_locale();

foreach ( $plans as $i => $plan ) {
	$plan = isset( $plan[ $locale ] ) ? $plan[ $locale ] : $plan['en_US'];

	if ( ! empty( $plan['price']['drop_month'] ) ) {
		// We use a discount based on a number of months free.
		$drop_type_tmp  = 'month';
		$drop_value_tmp = (int) $plan['price']['drop_month'];
	} else {
		// We use a discount based on a percentage off.
		$drop_type_tmp  = 'percent';
		$drop_value_tmp = (int) $plan['price']['drop_percent'];
	}

	if ( ! isset( $drop_type ) ) {
		$drop_type = $drop_type_tmp;
	} elseif ( $drop_type !== $drop_type_tmp ) {
		$drop_value = 0;
		break;
	}

	if ( ! isset( $drop_value ) ) {
		$drop_value = $drop_value_tmp;
	} elseif ( $drop_value !== $drop_value_tmp ) {
		$drop_value = 0;
		break;
	}
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
			<p class="secupress-text-medium"><?php esc_html_e( 'Pre-order SecuPress Pro Now and Get an Exclusive Discount', 'secupress' ); ?></p>
			<p><?php esc_html_e( 'Choose the licence that suits you the best and be one of the first users to get SecuPress Pro upon its release', 'secupress' ); ?></p>
		</div>
	</div>

	<div class="secupress-section">

		<p class="secupress-catchphrase"><?php printf( esc_html__( 'Improve Your Security by Unlocking%sAll the Features of SecuPress Pro', 'secupress' ), '<br/>' ); ?></p>

		<?php
		if ( isset( $impossible ) ) {
			echo $impossible;
		}
		?>

		<p class="secupress-inline-options secupress-text-center hide-if-no-js secupress-type-monthly">
			<button type="button" class="secupress-button secupress-inline-option secupress-current" data-type="monthly">
				<?php _e( 'Monthly', 'secupress' ); ?>
			</button>
			<button type="button" class="secupress-button secupress-inline-option" data-type="yearly">
				<?php
				_e( 'Yearly', 'secupress' );

				if ( $drop_value ) { ?>
					<span class="secupress-tip">
						<?php
						if ( 'month' === $drop_type ) {
							echo esc_html( sprintf( _n( '%1$d month free', '%1$d months free', (int) $drop_value, 'secupress' ), (int) $drop_value ) );
						} else {
							echo esc_html( sprintf( __( '%1$d%% OFF', 'secupress' ), (int) $drop_value ) );
						}
						?>
					</span>
					<?php
				}
				?>
			</button>
		</p>
		<div id="secupress-pricing" class="secupress-pricing secupress-flex secupress-text-center">
		<?php
		foreach ( $plans as $plan ) {
			$plan           = isset( $plan[ $locale ] ) ? $plan[ $locale ] : $plan['en_US'];
			$currency       = esc_html( $plan['price']['currency'] );
			$currency_after = 'before' !== $plan['price']['currency_pos'];
			// 1 is the currency symbol, 2 is the price.
			$price_template = $currency_after ? '%2$s%1$s' : '%1$s%2$s';
			$price_month    = explode( '.', esc_html( $plan['price']['month'] ) );

			if ( isset( $price_month[1] ) ) {
				$price_month = $price_month[0] . '<small>,' . $price_month[1] . '</small>';
			} else {
				$price_month = $price_month[0];
			}

			if ( ! empty( $plan['price']['drop_month'] ) ) {
				// We use a discount based on a number of months.
				$off_amount = (int) $plan['price']['drop_month'];
				$off_amount = sprintf( _n( '%1$d month free', '%1$d months free', $off_amount, 'secupress' ), $off_amount );
			} else {
				// We use a discount based on a percentage.
				$off_amount = sprintf( __( '%1$d%% OFF', 'secupress' ), (int) $plan['price']['drop_percent'] );
			}
			?>
			<div class="secupress-col-1-4 secupress-flex">
				<div class="secupress-price secupress-box-shadow secupress-flex-col">
					<div class="secupress-price-header">
						<p class="secupress-price-name"><?php echo esc_html( $plan['name'] ); ?></p>
						<p class="secupress-amounts secupress-hide-monthly">
							<?php
							printf( $price_template, '<span class="secupress-dollars">' . $currency . '</span>', '<ins>' . esc_html( $plan['price']['year'] ) . '</ins>' );
							printf( ' <del>' . $price_template . '</del>', $currency, esc_html( $plan['price']['year_old'] ) );
							?>
						</p>
						<p class="secupress-amounts secupress-hide-yearly">
							<?php printf( $price_template, '<span class="secupress-dollars">' . $currency . '</span>', '<span class="price">' . $price_month . '</span>' ); ?>
						</p>
						<p class="secupress-price-desc secupress-hide-monthly"><?php echo esc_html( $off_amount ); ?></p>
					</div>
					<div class="secupress-price-details">
						<p class="secupress-pd-info secupress-hide-monthly"><?php _e( 'Billed per year', 'secupress' ); ?></p>
						<p class="secupress-pd-info secupress-hide-yearly"><?php _e( 'Billed per month', 'secupress' ); ?></p>
						<p class="secupress-pd-benefits">
							<?php _e( 'Secure & Protect', 'secupress' ); ?>
							<?php if ( -1 < (int) $plan['websites'] ) { ?>
							<strong><?php echo esc_html( sprintf( _n( '%d Website', '%d Websites', (int) $plan['websites'], 'secupress' ), (int) $plan['websites'] ) ); ?></strong>
							<?php } else { ?>
							<strong><?php _ex( 'All your websites', 'websites', 'secupress' ); ?></strong>
							<?php } ?>
						</p>
					</div>
					<div class="secupress-price-cta">
						<a href="<?php echo esc_url( $plan['url']['year'] ); ?>" class="secupress-button secupress-button-primary shadow secupress-hide-monthly" target="_blank"><?php _e( 'Order', 'secupress' ); ?></a>
						<a href="<?php echo esc_url( $plan['url']['month'] ); ?>" class="secupress-button secupress-button-primary shadow secupress-hide-yearly" target="_blank"><?php _e( 'Order', 'secupress' ); ?></a>
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
