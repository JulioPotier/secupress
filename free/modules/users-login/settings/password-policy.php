<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'password_policy' );
$this->add_section( __( 'Password Policy', 'secupress' ), array( 'with_roles' => true ) );


$this->add_field( array(
	'title'        => __( 'Password Lifespan', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s days,<br/>0 = never expires', 'secupress' ), '30' ),
	'label_for'    => $this->get_field_name( 'password_expiration' ),
	'type'         => 'number',
	'value'        => ( secupress_is_submodule_active( 'users-login', 'password-expiration' ) ? null : 0 ),
	'label_after'  => __( 'days', 'secupress' ),
	'default'      => '0',
	'attributes'   => array(
		'min' => 0,
		'max' => 365,
	),
) );


$this->add_field( array(
	'title'             => __( 'Force Strong Passwords', 'secupress' ),
	'description'       => __( 'When a user is changing their password, a strong password will be required to continue.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'strong_passwords' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'strong-passwords' ),
	'label'             => __( 'Yes, force the use of strong passwords usage', 'secupress' ),
) );

