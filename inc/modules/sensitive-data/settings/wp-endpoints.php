<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'wp_endpoints' );
$this->add_section( __( 'WordPress Endpoints', 'secupress' ) );


$this->add_field( array(
	'title'        => __( 'XMLRPC', 'secupress' ),
	'description'  => __( 'If you don\'t use the XMLRPC, you can disable it and avoid to be targeted if a vulnerability is discovered.', 'secupress' ),
	'name'         => $this->get_field_name( 'xmlrpc' ),
	'type'         => 'radioboxes',
	'value'        => ( secupress_is_submodule_active( 'sensitive-data', 'xmlrpc' ) ? null : array() ),
	'options'      => array(
		'block-all'   => __( '<strong>Disable all</strong> the features for XMLRPC', 'secupress' ),
		'block-multi' => __( '<strong>Only disable</strong> the multiple authentication attempts', 'secupress' ),
	),
) );


$requires_wp_44_str = secupress_wp_version_is( '4.4' ) ? '' : '<br/>' . sprintf( __( 'Requires WordPress version %s or more.', 'secupress' ), '4.4' );

$this->add_field( array(
	'title'             => __( 'REST API', 'secupress' ),
	'description'       => __( 'If you don\'t use the REST API, you can disable it and avoid to be targeted if a vulnerability is discovered.', 'secupress' ) . $requires_wp_44_str,
	'label_for'         => $this->get_field_name( 'restapi' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'sensitive-data', 'restapi' ),
	'label'             => __( 'Yes, disable all the features of REST API', 'secupress' ),
	'disabled'          => (bool) $requires_wp_44_str,
) );
