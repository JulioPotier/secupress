<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'plugins_themes' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your plugins.', 'secupress' ) );
$this->add_section( __( 'Plugins Page', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'plugins'


$this->add_field(
	__( 'Plugins installation', 'secupress' ),
	array(
		'name'        => 'plugin_install_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_install_' . $plugin,
			'label'        => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
			'label_for'    => 'plugin_install_' . $plugin,
			'label_screen' => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_install_' . $plugin,
			'class'        => array( 'block-plugin_install_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Plugins activation', 'secupress' ),
	array(
		'name'        => 'plugin_activation_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_activation_' . $plugin,
			'label'        => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
			'label_for'    => 'plugin_activation_' . $plugin,
			'label_screen' => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_activation_' . $plugin,
			'class'        => array( 'block-plugin_activation_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Plugins deactivation', 'secupress' ),
	array(
		'name'        => 'plugin_deactivation_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_deactivation_' . $plugin,
			'label'        => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
			'label_for'    => 'plugin_deactivation_' . $plugin,
			'label_screen' => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_deactivation_' . $plugin,
			'class'        => array( 'block-plugin_deactivation_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Plugins deletion', 'secupress' ),
	array(
		'name'        => 'plugin_deletion_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_deletion_' . $plugin,
			'label'        => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
			'label_for'    => 'plugin_deletion_' . $plugin,
			'label_screen' => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_deletion_' . $plugin,
			'class'        => array( 'block-plugin_deletion_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Plugins updates', 'secupress' ),
	array(
		'name'        => 'plugin_update_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_update_' . $plugin,
			'label'        => __( 'Yes, disable the updates for all plugins', 'secupress' ),
			'label_for'    => 'plugin_update_' . $plugin,
			'label_screen' => __( 'Yes, disable the updates for all new plugins', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_update_' . $plugin,
			'class'        => array( 'block-plugin_update_' . $plugin ),
			'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);
