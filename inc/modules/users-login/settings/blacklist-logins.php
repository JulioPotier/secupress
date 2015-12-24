<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'blacklist-logins' );
$this->add_section( __( 'Usernames', 'secupress' ) );


$field_name = $this->get_field_name( 'activated' );

$this->add_field(
	__( 'Forbid usernames', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'users-login', 'blacklist-logins' ),
			'label'        => __( 'Yes, forbid users to use blacklisted usernames', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, forbid users to use blacklisted usernames', 'secupress' ),
		),
	)
);
