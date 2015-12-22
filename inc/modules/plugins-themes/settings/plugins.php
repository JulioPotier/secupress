<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'plugins_themes' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your plugins.', 'secupress' ) );
$this->add_section( __( 'Plugins Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$field_name = $this->get_field_name( 'update' );

$this->add_field(
	__( 'Plugins updates', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-update' ),
			'label'        => __( 'Yes, disable the updates for all plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the updates for all plugins', 'secupress' ),
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
	__( 'Plugins installation', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-installation' ),
			'label'        => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'activation' );

$this->add_field(
	__( 'Plugins activation', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string()
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-activation' ),
			'label'        => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name = $this->get_field_name( 'deactivation' );

$this->add_field(
	__( 'Plugins deactivation', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string()
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-deactivation' ),
			'label'        => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name = $this->get_field_name( 'deletion' );

$this->add_field(
	__( 'Plugins deletion', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string()
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-deletion' ),
			'label'        => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
	)
);


$field_name      = $this->get_field_name( 'detect_bad_plugins' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Detect Bad Plugins', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Work for any public plugin (premium and free).', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ),
			'label'        => __( 'Yes, enable the detection if a plugin I use is known as vulnerable', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, enable the detection if a plugin I use is known as vulnerable', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Based on our Daily Security Monitoring, we will push notices for plugins newly known as vulnerables.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'autoupdate_bad_plugins' );

$this->add_field(
	__( 'Auto-Update Bad Plugins', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Only for plugins from official repository.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br/>%s' ) )
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'autoupdate-bad-plugins' ),
			'label'        => __( 'Yes, also enable the auto-update if these plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, also enable the auto-update if these plugins', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'We will also push updates for plugins newly known as vulnerables.', 'secupress' ),
		),
	)
);
