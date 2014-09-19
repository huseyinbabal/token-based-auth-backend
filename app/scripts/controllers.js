'use strict';

/* Controllers */

angular.module('angularRestfulAuth')
    .controller('HomeCtrl', ['$rootScope', '$scope', '$location', 'Main', function($rootScope, $scope, $location, Main) {

        $scope.signin = function() {
            var formData = {
                email: $scope.email,
                password: $scope.password
            }

            Main.signin(formData, function(res) {
                $location.path('/me');
            }, function() {
                $rootScope.error = 'Failed to signin';
            })
        };

        $scope.me = function() {
            Main.me(function(res) {
                $scope.myDetails = res;
            }, function() {
                $rootScope.error = 'Failed to signin';
            })
        };

        $scope.logout = function() {
            Main.logout(function() {
                $location.path('/');
            }, function() {
                $rootScope.error = 'Failed to logout';
            });
        };
    }]);
