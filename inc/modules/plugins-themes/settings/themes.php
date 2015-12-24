<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$field_name = $this->get_field_name( 'update' );

$this->add_field(
	__( 'Theme update', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-update' ),
			'label'        => __( 'Yes, disable updates for themes', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable updates for themes', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'installation' );

$this->add_field(
	__( 'Theme installation', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-installation' ),
			'label'        => __( 'Yes, disable the installation for themes', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the installation for themes', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'activation' );

$this->add_field(
	__( 'Theme switch', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string()
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-activation' ),
			'label'        => __( 'Yes, disable switch theme', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable switch theme', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name = $this->get_field_name( 'deletion' );

$this->add_field(
	__( 'Theme deletion', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string()
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-deletion' ),
			'label'        => __( 'Yes, disable delete for theme', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable delete for theme', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name      = $this->get_field_name( 'detect_bad_themes' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Detect Bad Themes', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Work for any public theme, premium or free.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ),
			'label'        => __( 'Yes, enable the detection if a theme I use is known as vulnerable', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, enable the detection if a theme I use is known as vulnerable', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Based on our Daily Security Monitoring, we will push notices for themes newly known as vulnerables.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'autoupdate_bad_themes' );

$this->add_field(
	__( 'Auto-Update Bad Themes', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Only for themes from official repository.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br/>%s') )
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'autoupdate-bad-themes' ),
			'label'        => __( 'Yes, enable the auto-update if a theme I use is known as vulnerable', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, enable the auto-update if a theme I use is known as vulnerable', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Based on our Daily Security Monitoring, we will push updates for themes newly known as vulnerables.', 'secupress' ),
		),
	)
);