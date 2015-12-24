<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'password_policy' );
$this->add_section( __( 'Password Policy', 'secupress' ), array( 'with_roles' => true ) );


$field_name = $this->get_field_name( 'password_expiration' );
$this->add_field(
	__( 'Passwords Lifetime', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s days,<br>0 = never expires', 'secupress' ), '30' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'number',
			'min'          => 0,
			'max'          => 365,
			'name'         => $field_name,
			'value'        => ( secupress_is_submodule_active( 'users-login', 'password-expiration' ) ? null : 0 ),
			'label_for'    => $field_name,
			'label'        => __( 'days', 'secupress' ),
			'default'      => '0',
			'label_screen' => __( 'Passwords lifetime', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name = $this->get_field_name( 'strong_passwords' );
$this->add_field(
	__( 'Force Strong Passwords', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a user is changing his password, a strong password will be required to continue.', 'secupress' ) . ( secupress_valid_key() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'users-login', 'strong-passwords' ),
			'label'        => __( 'Yes, force a strong passwords usage', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, force a strong passwords usage', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);
