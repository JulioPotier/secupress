<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wp_version;
$requires_wp_44_str = version_compare( '4.4', $wp_version ) >= 0 ? '<p class="description">' . __( 'Requires WordPress Version:' ) . ' ' . sprintf( __( '%s or more', 'secupress' ), '4.4' ) .'</p>' : false;

$this->set_current_section( 'wp_endpoints' );
$this->add_section( __( 'WordPress Endpoints', 'secupress' ) );


$field_name = $this->get_field_name( 'xmlrpc' );
$this->add_field(
	__( 'XMLRPC', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'If you don\'t use the XMLRPC, you can disable it and avoid to be targeted if a vulnerability is discovered.', 'secupress' ) . $requires_wp_44_str,
	),
	array(
		array(
			'type'         => 'checkboxes',
			'name'         => $field_name,
			'options'      => array( 
									'block-all'   => __( '<strong>Disable all</strong> the features for XMLRPC', 'secupress' ), 
									'block-multi' => __( '<strong>Only disable</strong> the multiple authentication attempts', 'secupress' ) 
								),
			'label_for'    => $field_name,
			'label_screen' => __( 'Disable all features or only multi authentication attemps for XMLRPC', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'restapi' );
$this->add_field(
	__( 'REST API', 'secupress' ) . $requires_wp_44_str,
	array(
		'name'        => $field_name,
		'description' => __( 'If you don\'t use the REST API, you can disable it and avoid to be targeted if a vulnerability is discovered.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable all the features of REST API', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable all the features of REST API', 'secupress' ),
			'readonly'     => (bool) $requires_wp_44_str,
		),
	)
);
