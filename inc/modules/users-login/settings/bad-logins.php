<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'login_auth3' );
$this->add_section( __( 'Usernames', 'secupress' ) );


$field_name      = $this->get_field_name( 'blacklist-logins' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Forbid usernames', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, forbid users to use blacklisted usernames', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, forbid users to use blacklisted usernames', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Create a list of forbidden usernames.', 'secupress' ),
		),
	)
);


$field_name    = $this->get_field_name( 'blacklist-logins-list' );
$allowed_chars = secupress_blacklist_logins_allowed_characters( true );
$allowed_chars = str_replace( sprintf( __('%s, %s'), '<code>A-Z</code>', '' ), '' , $allowed_chars );

$this->add_field(
	__( 'List of forbidden usernames', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Users won\'t be able to use any of the following usernames. The users already using one of those will be asked to change it.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'        => 'textarea',
			'name'        => $field_name,
			'label_for'   => $field_name,
		),
		array(
			'type'        => 'helper_description',
			'name'        => $field_name,
			'description' => __( 'One username per line, lowercase.', 'secupress' ) . '<br/>' . __( '<code>admin</code> and <em>one character usernames</em> are automatically blacklisted.', 'secupress' ) . '<br/>' . $allowed_chars,
		),
	)
);
