<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'page_protect' );
$this->add_section( __( 'Pages Protection', 'secupress' )/*, array( 'with_roles' => true )*/ );


$field_name = $this->get_field_name( 'profile' );

$this->add_field(
	__( 'Protect the profile page', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, protect the profile pages', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect the profile pages', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'depends_on'   => $field_name,
			'description'  => __( 'By using this protection, nobody can stalk into your profile page when you left your computer.', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'settings' );

$this->add_field(
	sprintf( __( 'Protect %s settings page', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
	array(	
			'name' => $field_name,
			'description' => __( 'We recommand to protect the settings page once your settings are done.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
		),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, protect the settings pages', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect the settings pages', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'depends_on'   => $field_name,
			'description'  => __( 'By using this protection, nobody can stalk into the settings page when you left your computer.', 'secupress' ),
		),
	)
);
