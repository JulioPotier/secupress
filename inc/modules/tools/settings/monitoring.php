<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'monitoring' );
$this->add_section( __( 'Uptime Monitoring', 'secupress' ) );


$this->add_field( array(
	'title'        => __( 'Monitor my website', 'secupress' ),
	'description'  => sprintf(
		__( 'This tool will alert you when your site is down. Every %s minutes our robot check this website. If it\'s down, you will be immediately notified by email. Once back, you will be notified to.', 'secupress' ),
		'<strong>' . ( secupress_is_pro() ? '5' : '60' ) . '</strong>' //// voir avec jb pour le timing
	) . ( secupress_is_pro() ? '' : secupress_get_valid_key_string( '<br/>%s' ) ),
	'label_for'    => $this->get_field_name( 'activate' ),
	'type'         => 'checkbox',
	'label'        => __( 'Yes, monitor the uptime of my website and alert me if needed', 'secupress' ),
	'disabled'     => ! secupress_valid_key(),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => sprintf( __( 'The following email address will be used: %s', 'secupress' ), '<code>' . '???' . '</code>' ), //// adresse mail de l'inscription de la clé API
		),
	),
) );
