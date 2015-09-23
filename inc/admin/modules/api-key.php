<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


if ( ! function_exists( '__secupress_how_to_get_licence' ) ) {
	function __secupress_how_to_get_licence() {
		$description = array(
			'<strong>' . __( 'Why an API key?', 'secupress' ) . '</strong>',
			__( 'The API Key is needed for our module linked to the services depending of our servers, like <em>website monitoring</em> or <em>plugins vulnerability check discovery</em> in live.', 'secupress' ),
			sprintf( __( '%s or just <strong>enter your email address</strong> below and <strong>save</strong> to get a free account.', 'secupress' ), '<a href="" target="_blank">' . __( 'Buy a licence to unlock all the features', 'secupress' ) . '</a>' ),
		);

		return implode( "<br/>\n", $description );
	}
}


$this->set_current_section( 'secupress_display_apikey_options' );
$this->set_section_description( __secupress_how_to_get_licence() );
$this->add_section( __( 'License validation', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'api-key'

$this->add_field(
	__( 'E-mail Address', 'secupress' ),
	array(
		'name'        => $plugin . '_email',
	),
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

$this->add_field(
	__( 'API Key', 'secupress' ),
	array(
		'name'        => $plugin . '_api_key',
	),
	array(
		array(
			'type'         => 'text',
			'label_for'    => 'consumer_key',
			'label_screen' => __( 'API Key', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => 'consumer_key',
			'description'  => __( 'Please enter the API key obtained with your account or leave blank and save to get a free account.', 'secupress' )
		),
	)
);
