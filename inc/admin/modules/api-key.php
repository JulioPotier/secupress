<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_settings_section( 'secupress_display_apikey_options', __( 'License validation', 'secupress' ), '__secupress_how_to_get_licence', 'secupress_api-key' );

add_settings_field(
	'secupress_email',
	__( 'E-mail Address', 'secupress' ),
	'secupress_field',
	'secupress_api-key',
	'secupress_display_apikey_options',
	array(
		array(
			'type'         => 'email',
			'label_for'    => 'consumer_email',
			'label_screen' => __( 'E-mail Address', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => 'consumer_email',
			'description'  => 	__( 'The one you got with your account or enter your own and save to get a free account.', 'secupress' ),
		),
	)
);

add_settings_field(
	'secupress_api_key',
	__( 'API Key', 'secupress' ),
	'secupress_field',
	'secupress_api-key',
	'secupress_display_apikey_options',
	array(
		array(
			'type'			=> 'text',
			'label_for'		=> 'consumer_key',
			'label_screen'	=> __( 'API Key', 'secupress' ),
		),
		array(
			'type'			=> 'helper_help',
			'name'			=> 'consumer_key',
			'description'	=> __( 'Please enter the API key obtained with your account or leave blank and save to get a free account.', 'secupress' )
		),		
	)
);

if ( ! function_exists( '__secupress_how_to_get_licence' ) ) {
	function __secupress_how_to_get_licence() {
		_e( '<b>Why an API key?</b><br>The API Key is needed for our module linked to the services depending of our servers, like <i>website monitoring</i> or <i>plugins vulnerability check discovery</i> in live.', 'secupress' );
		echo '<br>';
		_e( '<a href="%1$s" target="_blank">Buy a licence to unlock all the features</a> or just <b>enter your email address</b> below and <b>save</b> to get a free account.', 'secupress' );
		echo '<hr>';
	}
}