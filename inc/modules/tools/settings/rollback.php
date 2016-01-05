<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'rollback' );
$this->add_section( __( 'Rollbacks', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => ! secupress_is_pro() ? __( 'Rollback', 'secupress' ) : __( 'Rollback (free version)', 'secupress' ),
	'description'  => sprintf( __( 'Is the free version %s causing you some issues? You can ask for a rollback and reinstall the last version you used before.', 'secupress' ), SECUPRESS_VERSION ),
	'name'         => $this->get_field_name( 'rollback_free' ),
	'field_type'   => 'field_button',
	'label'        => sprintf( __( 'Reinstall v%s', 'secupress' ), SECUPRESS_LASTVERSION ),
	'url'          => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_rollback_free' ), 'secupress_rollback_free' ),
	'helpers'      => array(
		array(
			'type'        => 'warning',
			'description' => __( 'Please backup your settings before, use the "Download settings" button above.', 'secupress' ),
		),
	)
) );


if ( secupress_is_pro() ) {
	//// doc hook
	do_action( 'module.pro.rollback' );
}
