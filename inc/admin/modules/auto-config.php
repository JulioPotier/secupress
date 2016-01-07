<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


$this->set_current_section( 'secupress_auto-config' );
$this->set_section_description( __( 'You can trust in our auto setting configuration. Depending on your needs, just select and save, we will handle this for you.', 'secupress' ) );
$this->add_section( __( 'Auto configuration <strong><em>(optional)</em></strong>', 'secupress' ) );


$field_name = $this->get_field_name( 'level' );

$this->add_field( array(
	'title'        => __( 'Level of configuration', 'secupress' ),
	'label_for'    => $field_name . '_4',
	'type'         => 'radios',
	// 4 = high ; 3 = default ; 2 = low ; 1 = guess :)
	'options'      => array(
		4 => __( '<strong>High level</strong> This is a very restrictive configuration, you could need it when you think you are under attack.', 'secupress' ),
		3 => __( '<strong>Default level</strong> This configuration is the one we used when you activated the plugin.', 'secupress' ),
		2 => __( '<strong>Low level</strong> We will just protect the minimum things a website can need avoiding to be blocking.', 'secupress' ),
		1 => __( '<strong>Custom</strong> Your own settings!', 'secupress' ),
	),
	'name'         => $field_name,
	'default'      => 3,
	'label_screen' => __( 'Auto configuration', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'help',
			/* Translators: %s is "little video". */
			'description' => sprintf( __( 'Still hesitating? Watch this %s, it will help you decide.', 'secupress' ), '<a href="#">' . __( 'little video', 'secupress' ) . '</a>' ),
		),
	)
) );
