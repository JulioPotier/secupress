<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'login_auth2' );
$this->add_section( __( 'Limit Login Attempts', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'bad_logins'


$select_args_options = apply_filters( 'module_' . $plugin, array(
	'limitloginattempts' => __( 'Limit the number of bad login attempts', 'secupress' ),
	'_ooc'               => __( 'Use the Only One Connection mode', 'secupress' ),
	'bannonexistsuser'   => __( 'Ban login attempts on non-existing usernames', 'secupress' ),
	'nonlogintimeslot'   => __( 'Set a non-login time slot', 'secupress' ),
) );

$field_name = $this->get_field_name( 'type' );
$this->add_field(
	__( 'Use an attempt blocker', 'secupress' ),
	array(
		'name'        => 'plugin_' . $plugin,
		'description' => __( 'You can temporary ban people who try to mess with the login page. This is recommended to avoid to be victim of a brute-force.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkboxes',
			'options'      => $select_args_options,
			'name'         => 'plugin_' . $plugin,
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Limit Login Attempts choice', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-limitloginattempts', 'block-plugin_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Premium Upgrade', 'secupress' ),
	array(
		'name'       => '',
		'field_type' => 'field_button',
	),
	array(
		'class'              => static::hidden_classes( 'hidden block-_ooc block-plugin_' . $plugin ),
		'helper_description' => array(
			'description'    => __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' ) . '<br>' . __( 'Once logged in, nobody can log in on your account at the same time as you.', 'secupress' ),
		),
		'button'             => array(
			'url'            => '#',
			'button_label'   => __( 'I Upgrade Now', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'How many attempts before a ban?', 'secupress' ),
	array(
		'name'        => $plugin . '_number_attempts',
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '10 - 50' ),
	),
	array(
		'class'       => static::hidden_classes( 'block-limitloginattempts block-plugin_' . $plugin ),
		array(
			'type'         => 'number',
			'min'          => 3,
			'max'          => 99,
			'name'         => $plugin . '_number_attempts',
			'label_for'    => $plugin . '_number_attempts',
			'label'        => '',
			'default'      => '10',
			'label_screen' => __( 'How many attempt before a ban?', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'How long should we ban?', 'secupress' ),
	array(
		'name'        => $plugin . '_time_ban',
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	),
	array(
		'class'       => static::hidden_classes( 'block-limitloginattempts block-bannonexistsuser block-plugin_' . $plugin ),
		array(
			'type'         => 'number',
			'min'          => 1,
			'max'          => 60,
			'name'         => $plugin . '_time_ban',
			'label_for'    => $plugin . '_time_ban',
			'label'        => __( ' mn', 'secupress' ),
			'default'      => '5',
			'label_screen' => __( 'How long should we ban?', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'Non-Login time slot settings', 'secupress' ),
	array(
		'name'        => $plugin . '_nonlogintimeslot',
		'description' => '',
	),
	array(
		'class'       => static::hidden_classes( 'block-nonlogintimeslot block-plugin_' . $plugin ),
		array(
			'type'         => 'nonlogintimeslot',
			'name'         => $plugin . '_nonlogintimeslot',
			'label_for'    => $plugin . '_nonlogintimeslot',
			'label'        => '',
			'label_screen' => __( 'Non-Login time slot', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-nonlogintimeslot', 'block-plugin_' . $plugin ),
			'description'  => __( 'Select the range of time you need to disallow logins.', 'secupress' ),
		),
	)
);
