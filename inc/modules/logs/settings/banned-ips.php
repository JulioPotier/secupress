<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'banned-ips' );
$this->set_section_description( __( 'When you need to (dis)allow access to your website to some servers by their IP.', 'secupress' ) );
$this->add_section( __( 'IP Adresses', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Disallowed IPs', 'secupress' ),
	'description'  => __( 'Bots, servers, visitors with those IP addresses will <strong>never</strong> have the right to visit your website.', 'secupress' ),
	'name'         => $this->get_field_name( 'banned-ips' ),
	'type'         => 'blacklist_ips',
	'row_id'       => 'banned-ips-row',
) );


$this->add_field( array(
	'title'        => __( 'Allowed IPs', 'secupress' ),
	'description'  => __( 'Bots, servers, visitors with those IP addresses will <strong>always</strong> have the right to visit your website. This list has priority over all.', 'secupress' ),
	'label_for'    => $this->get_field_name( 'whitelist' ),
	'type'         => 'whitelist_ips',
	'row_id'       => 'whitelist-ips-row',
) );
