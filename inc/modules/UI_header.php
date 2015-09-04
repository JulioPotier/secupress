<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );
settings_errors();
global $modulenow, $secupress_modules;
if ( 'welcome' == $modulenow ) {
	return; // no module loaded
}
add_settings_section( 'module_' . $modulenow, __( 'Module activation', 'secupress' ), '__rocket_module_full_title', 'module_' . $modulenow );
	add_settings_field(
	'module_' . $modulenow . '_active',
	__( 'Module activated?', 'rocket' ),
	'secupress_field',
	'module_' . $modulenow,
	'module_' . $modulenow,
	array(
		array(
			'type'			=> 'checkbox',
			'label'    		=> sprintf( __( 'Yes, activate the %s modules.', 'secupress' ), get_secupress_module_title() ),
			'label_for'		=> 'module_active',
			'label_screen'	=> __( 'Module active:', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'advanced_options',
			'description'  =>  __( 'You can select and configure each module separately below.', 'secupress' ),
		),
	)
);

/**
*
*/
function __rocket_module_full_title() {
	echo '<div class="notice notice-success"><i>' . __( 'This will activate all the sub-modules, for more accuracy, let this first box checked, then you can select which ones you need by expanding the advanced options.', 'secupress' ) . '</i></div>';
}
?>
<div class="secublock">
	<h3><?php echo $secupress_modules[ $modulenow ]['title']; ?></h3>
	<?php
	foreach ( $secupress_modules[ $modulenow ]['description'] as $description ) {
		echo "<p>$description</p>\n";
	}
	?>
</div>
<form id="secupress-module-form-settings" method="post" action="<?php echo admin_url( 'options.php' ); ?>">
<?php
do_secupress_settings_sections( 'module_' . $modulenow );
secupress_submit_button( 'primary large' );
$class_hidden = secupress_is_module_active( $modulenow ) ? '' : 'hide-if-js';
?>
<div id="block-advanced_options" data-module="<?php echo $modulenow; ?>" class="<?php echo $class_hidden; ?>">