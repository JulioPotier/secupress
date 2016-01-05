<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'banned-ips' );
$this->add_section( __( 'Banned IPs', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Actually Banned IPs', 'secupress' ),
	'description'  => __( 'Some modules are made to ban bad IPs addresses, you can see it and unban it if needed', 'secupress' ),
	'name'         => $this->get_field_name( 'banned-ips' ),
	'type'         => 'banned_ips',
) );
