<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'rollback' );
$this->add_section( __( 'Rollbacks', 'secupress' ), array( 'with_save_button' => false ) );

$helper_warning = array( 'name' => 'rollback_free2', 'description' => __( 'Please backup your settings before, use the "Download settings" button above.', 'secupress' ), );
$module_title   = ! secupress_is_pro() ? __( 'Rollback', 'secupress' ) : __( 'Rollback (free version)', 'secupress' );

$field_name     = $this->get_field_name( 'rollback_free' );
$this->add_field(
	$module_title,
	array(
		'name'        => $field_name,
		'field_type'  => 'field_button',
    	'description' => sprintf( __( 'Is the free version %s causing you some issues? You can ask for a rollback and reinstall the last version you used before.', 'secupress' ), SECUPRESS_VERSION ),
	),
	array(
        'button'=>array(
        	'button_label'   => sprintf( __( 'Reinstall v%s', 'secupress' ), SECUPRESS_LASTVERSION ),
        	'url'		     => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_rollback_free' ), 'secupress_rollback_free' ),
        ),
		'helper_description' => array(
			'name'           => 'rollback_free',
		),
		'helper_warning'     => $helper_warning,
	)
);

if ( secupress_is_pro() ) {
	//// doc hook
	do_action( 'module.pro.rollback' );
}