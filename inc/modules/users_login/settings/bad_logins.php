<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow;

$sectionnow = 'login_auth2';
$pluginnow  = 'bad_logins';

secupress_add_settings_section( __( 'Limit Login Attempts', 'secupress' ) );

$select_args_options = apply_filters( 'module_' . $pluginnow, array(
	'limitloginattempts' => __( 'Limit the number of bad login attempts', 'secupress' ),
	'_ooc'               => __( 'Use the Only One Connection mode', 'secupress' ),
	'bannonexistsuser'   => __( 'Ban login attempts on non-existing usernames', 'secupress' ),
	'nonlogintimeslot'   => __( 'Set a non-login time slot', 'secupress' ),
) );

secupress_add_settings_field(
	__( 'Use an attempt blocker', 'secupress' ),
	array(
		'description' => __( 'You can temporary ban people who try to mess with the login page. This is recommanded to avoid to be victim of a brute-force.', 'secupress' ),
		'name'        => 'plugin_' . $pluginnow,
	),
	array(
		array(
			'type'         => 'checkboxes',
			'options'      => $select_args_options,
			'name'         => 'plugin_' . $pluginnow,
			'label_for'    => 'plugin_' . $pluginnow,
			'label_screen' => __( 'Limit Login Attempts choice', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $pluginnow,
			'class'        => array( 'hidden', 'block-hidden', 'block-limitloginattempts', 'block-' . 'plugin_' . $pluginnow ),
		),
	)
);

secupress_add_settings_field(
	__( 'Premium Upgrade', 'secupress' ),
	array(
		'field_type' => 'button',
		'name'       => '',
	),
	array(
		'class'              => __secupress_get_hidden_classes( 'hidden block-_ooc block-plugin_' . $pluginnow ),
		'helper_description' => array(
			'description'    => __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' ) . '<br>' . __( 'Once logged in, nobody can log in on your account at the same time as you.', 'secupress' ),
		),
		'button'             => array(
			'url'            => '#',
			'button_label'   => __( 'I Upgrade Now', 'secupress' ),
		),
	)
);

secupress_add_settings_field(
	__( 'How many attempts before a ban?', 'secupress' ),
	array(
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '10 - 50' ),
		'name'        => $pluginnow . '_number_attempts'
	),
	array(
		'class'       => __secupress_get_hidden_classes( 'block-limitloginattempts block-plugin_' . $pluginnow ),
		array(
			'type'         => 'number',
			'min'          => 3,
			'max'          => 99,
			'name'         => $pluginnow . '_number_attempts',
			'label_for'    => $pluginnow . '_number_attempts',
			'label'        => '',
			'default'      => '10',
			'label_screen' => __( 'How many attempt before a ban?', 'secupress' ),
		),
	)
);

secupress_add_settings_field(
	__( 'How long should we ban?', 'secupress' ),
	array(
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
		'name'        => $pluginnow . '_time_ban'
	),
	array(
		'class'       => __secupress_get_hidden_classes( 'block-limitloginattempts block-bannonexistsuser block-plugin_' . $pluginnow ),
		array(
			'type'         => 'number',
			'min'          => 1,
			'max'          => 60,
			'name'         => $pluginnow . '_time_ban',
			'label_for'    => $pluginnow . '_time_ban',
			'label'        => __( ' mn', 'secupress' ),
			'default'      => '5',
			'label_screen' => __( 'How long should we ban?', 'secupress' ),
		),
	)
);

secupress_add_settings_field(
	__( 'Non-Login time slot settings', 'secupress' ),
	array(
		'description' => '',
		'name'        => $pluginnow . '_nonlogintimeslot'
	),
	array(
		'class'       => __secupress_get_hidden_classes( 'block-nonlogintimeslot block-plugin_' . $pluginnow ),
		array(
			'type'         => 'nonlogintimeslot',
			'name'         => $pluginnow . '_nonlogintimeslot',
			'label_for'    => $pluginnow . '_nonlogintimeslot',
			'label'        => '',
			'label_screen' => __( 'Non-Login time slot', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $pluginnow,
			'class'        => array( 'hidden', 'block-hidden', 'block-nonlogintimeslot', 'block-' . 'plugin_' . $pluginnow ),
			'description'  => __( 'Select the range of time you need to disallow logins.', 'secupress' ),
		),
	)
);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );
