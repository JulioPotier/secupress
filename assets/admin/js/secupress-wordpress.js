/* globals jQuery: false, ajaxurl: false, SecuPressi18n: false, swal2: false */
// !Global vars ====================================================================================
var SecuPress = {
	swal2Defaults:        {
		confirmButtonText: SecuPressi18n.confirmText,
		cancelButtonText:  SecuPressi18n.cancelText,
		type:              "warning",
		allowOutsideClick: true,
		customClass:       "wpmedia-swal2 secupress-swal2"
	},
	swal2ConfirmDefaults: {
		showCancelButton: true,
		closeOnConfirm:   false
	}
};
/**
 * Basic tools
 */
// Shorthand to tell if a modifier key is pressed.
function secupressHasModifierKey( e ) {
	return e.altKey || e.ctrlKey || e.metaKey || e.shiftKey;
}
// Shorthand to tell if the pressed key is Space or Enter.
function secupressIsSpaceOrEnterKey( e ) {
	return ( e.which === 13 || e.which === 32 ) && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Space.
function secupressIsSpaceKey( e ) {
	return e.which === 32 && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Enter.
function secupressIsEnterKey( e ) {
	return e.which === 13 && ! secupressHasModifierKey( e );
}
// Shorthand to tell if the pressed key is Escape.
function secupressIsEscapeKey( e ) {
	return e.which === 27 && ! secupressHasModifierKey( e );
}

jQuery( document ).ready( function( $ ) {

	// Themes page: Move the "div alert" when a theme is vulnerable. ===============================
	(function($, d, w, undefined) {

		$( ".secupress-bad-theme" ).each( function( index, html ) {
			var $theme = $( "*[data-slug='" + $( this ).attr( "data-theme" ) + "']" );
			$theme.find( ".theme-actions .activate, .theme-actions .load-customize" ).remove();
			if ( $theme.find( ".update-message" ).length > 0 ) {
				$(html).css('top', '40px');
			}
			$theme.find( ".theme-screenshot" ).after( html );
		} );

	} )(jQuery, document, window);

	// Plugins page: Remove notice when clicking on update link and update admin bar color. =======
	(function($) {
		'use strict';
		
		// Only run on plugins page
		if ( ! $( 'body.plugins-php' ).length ) {
			return;
		}
		
		// Listen for clicks on update links (class .update-link or links containing upgrade-plugin)
		$(document).on('click', 'a.update-link, a[href*="update.php?action=upgrade-plugin"]', function(e) {
			var $link = $(this);
			var href = $link.attr('href') || '';
			
			// Extract nonce from URL
			var nonceMatch = href.match(/_wpnonce=([^&]+)/);
			if (!nonceMatch || !nonceMatch[1]) {
				return; // No nonce found, let the link work normally
			}
			
			// Extract plugin file from URL to find the corresponding notification
			var pluginMatch = href.match(/plugin=([^&]+)/);
			var $noticeLi = $(); // Empty jQuery object
			
			// Find notification by plugin file (most reliable method)
			// The nonce is used to generate a unique ID, but we match by plugin file
			if (pluginMatch && pluginMatch[1]) {
				var pluginFile = decodeURIComponent(pluginMatch[1]);
				// Escape special characters for jQuery selector
				pluginFile = pluginFile.replace(/"/g, '\\"').replace(/'/g, "\\'");
				$noticeLi = $('li[data-plugin-file="' + pluginFile + '"]');
			}
			
			// Remove the notification if found
			if ($noticeLi.length > 0) {
				var $list = $noticeLi.closest('ul');
				var $notice = $noticeLi.closest('.secupress-notice, .notice, div[class*="notice"]');
				
				// If the list will be empty after removing this item, remove the entire notice
				if ($list.length > 0 && $list.find('li').length === 1) {
					if ($notice.length === 0) {
						$notice = $list.closest('.secupress-notice, .notice, div[class*="notice"]');
					}
					if ($notice.length > 0) {
						$notice.fadeOut(300, function() {
							$(this).remove();
							updateAdminBarColor();
						});
					} else {
						$list.fadeOut(300, function() {
							$(this).remove();
							updateAdminBarColor();
						});
					}
				} else {
					// Just remove the list item
					$noticeLi.fadeOut(300, function() {
						$(this).remove();
						updateAdminBarColor();
					});
				}
			}
		});
		
		/**
		 * Update the admin bar updates background color based on the last remaining notice.
		 */
		function updateAdminBarColor() {
			// Color mapping (same as PHP)
			var colors = {
				'info': '#26B3A9',
				'warning': '#F7AB13',
				'error': '#F2295E'
			};
			
			// Find all secupress-mini-notice divs
			var $notices = $('.secupress-mini-notice');
			
			if ($notices.length === 0) {
				// No notices left, remove custom background color (restore default)
				$('#wpadminbar #wp-admin-bar-updates').css('background-color', '');
				// Remove any inline style tag we might have added
				$('style[data-secupress-admin-bar-color]').remove();
				return;
			}
			
			// Get the last notice in the DOM (the one that appears last)
			var $lastNotice = $notices.last();
			var color = '';
			var noticeClasses = $lastNotice.attr('class') || '';
			
			// Check which class the notice has (info, warning, or error)
			// The classes are like: "notice notice-error notice-alt secupress-mini-notice" or similar
			// Priority: error > warning > info (same as PHP logic)
			if (noticeClasses.indexOf('notice-error') !== -1 || noticeClasses.indexOf('error') !== -1) {
				color = colors.error;
			} else if (noticeClasses.indexOf('notice-warning') !== -1 || noticeClasses.indexOf('warning') !== -1) {
				color = colors.warning;
			} else if (noticeClasses.indexOf('notice-info') !== -1 || noticeClasses.indexOf('info') !== -1) {
				color = colors.info;
			}
			
			// Apply the color to the admin bar updates menu
			if (color) {
				// Remove any existing inline style
				$('style[data-secupress-admin-bar-color]').remove();
				// Add or update the style
				$('head').append('<style type="text/css" data-secupress-admin-bar-color>#wpadminbar #wp-admin-bar-updates { background-color: ' + color + ' !important; }</style>');
			} else {
				// If no color found, remove custom styling
				$('#wpadminbar #wp-admin-bar-updates').css('background-color', '');
				$('style[data-secupress-admin-bar-color]').remove();
			}
		}
	})(jQuery);

} );
