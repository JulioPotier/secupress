<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );
settings_errors();
global $modulenow, $secupress_modules;
if ( 'welcome' == $modulenow ) {
	return; // no module loaded
}
//// todo save settings with history
add_settings_section( 'module_' . $modulenow, __( 'Module settings', 'secupress' ), '__rocket_module_full_title', 'module_' . $modulenow );
	add_settings_field(
	'module_' . $modulenow . '_settings',
	__( 'Reset settings?', 'rocket' ),
	'secupress_button',
	'module_' . $modulenow,
	'module_' . $modulenow,
	array( 'button' =>
		array(
			'url'			=> wp_nonce_url( admin_url( 'admin-post.php?action=secupress_reset_settings&module=' . $modulenow ), 'secupress_reset_' . $modulenow ),
			'button_label'    		=> sprintf( __( 'Reset the %s\'s settings.', 'secupress' ), secupress_get_module_title() ),
		),
		// array(
		// 	'type'         => 'helper_description',
		// 	'name'         => 'advanced_options',
		// 	'description'  =>  __( 'You can select and configure each module separately below.', 'secupress' ),
		// ),
	)
);

/**
*
*/
function __rocket_module_full_title() {
	echo '<div class="notice notice-success"><i>' . __( 'If you need to reset this module\'s settings to the default ones, you just have to do it here, we will set the best for your site.', 'secupress' ) . '</i></div>';
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
?>
<div id="block-advanced_options" data-module="<?php echo $modulenow; ?>">