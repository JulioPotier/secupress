<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Add the form manually since i just need it for this block.
add_action( 'secupress.settings.before_section_bad-file-extensions', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_bad-file-extensions', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'bad-file-extensions' );
$this->set_section_description( __( 'Many file extensions are known to be used by malwares, or can pose a threat if they are vulnerable. Denying direct access to those files will prevent their use.', 'secupress' ) );
$this->add_section( __( 'Bad File Extensions', 'secupress' ) );

$this->add_field( array(
	'title'             => __( 'Uploads folder', 'secupress' ),
	'name'              => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'file-system', 'bad-file-extensions' ),
	'label'             => __( 'Deny direct access to those files in the uploads folder.', 'secupress' ),
) );
