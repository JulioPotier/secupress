jQuery( document ).ready( function( $ ) {

// Themes page: Move the "div alert" when a theme is vulnerable. =================================
(function($, d, w, undefined) {

	$( ".secupress-bad-theme" ).each( function( index, html ) {
		var $theme = $( "#" + $( this ).attr( "data-theme" ) + "-name" );
		$theme.parent().find( ".theme-update" ).remove();
		$theme.parent().find( ".theme-actions .activate" ).remove();
		$theme.after( html );
	} );

} )(jQuery, document, window);

} );