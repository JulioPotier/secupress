<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->add_section( __( 'SecuPress PRO', 'secupress' ), array( 'with_save_button' => false ) );

$this->add_field( array(
	'title'        => __( 'SecuPress version PRO', 'secupress' ),
	'description'  => __( 'Discover our pro version.', 'secupress' ),
	'name'         => $this->get_field_name( 'get-pro' ),
	'field_type'   => 'field_button',
	'label'        => __( 'Get SecuPress PRO', 'secupress' ),
	'url'          => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_pro' ), 'secupress_get_pro' ),
) );
