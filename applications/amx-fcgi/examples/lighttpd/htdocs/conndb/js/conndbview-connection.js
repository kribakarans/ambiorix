(function (conndbview, $, undefined) {
    (function (connection, $, undefined) {
        let init = false;
        var scrollPos = 0;

        function saveScrollPos() {
            scrollPos = $("#ConnTable_wrapper .dataTables_scrollBody").scrollTop();
        }

        function loadScrollPos() {
            $("#ConnTable_wrapper .dataTables_scrollBody").scrollTop(scrollPos);
        }

        connection.startupdate = function() {
            saveScrollPos();
            $('#ConnTable tbody tr').addClass('remove');
        }
        
        connection.updaterow = function(conn, service) {
            var datatable = $('#ConnTable').DataTable();
            let rownode = $('#connection' + conn.id + '_row');
            var rows = datatable.rows(rownode).data();

            var addRow = {
                sourceip: conn.srcIP,
                destip: conn.dstIP,
                protocol: conn.protocol,
                srcport: conn.srcport,
                destport: conn.dstport,
                traffictype:conn.connection_type,
                service: service,
                identifier: conn.service_identifier,
                pattern: conn.pattern_matched.localeCompare("NULL")?conn.pattern_matched:"",
            }
            if(rows.length > 0) {
                $(rownode).removeClass('remove');
            } else {
                rownode = datatable.row.add(addRow).draw().node();
                $(rownode).attr('id','connection' + conn.id + '_row');
                $(rownode).removeClass('remove');
            }
        }

        connection.endupdate = function() {
            var datatable = $('#ConnTable').DataTable();
            let rows = datatable.rows('.remove');

            if(rows.length > 0) {
                rows.remove().draw();
            }

            loadScrollPos();
        }

        connection.clear = function() {
            var datatable = $('#ConnTable').DataTable();
            datatable.rows().remove().draw();
        }

        connection.init = async function() {
            if(init) {
                return;
            }

            let connection_table = await window.templates.load("connection-table");

            $('body .content').append(connection_table);

            $('#ConnTable')
            .DataTable({
                dom: 'rt',
                columns: [
                    { data: 'sourceip' },
                    { data: 'destip' },
                    { data: 'protocol' },
                    { data: 'srcport' },
                    { data: 'destport' },
                    { data: 'traffictype' },
                    { data: 'service' },
                    { data: 'identifier' },
                    { data: 'pattern' },
                ],

                stateSave: true,
    
                "paging": false,
                "ordering": true,
                "info": false,

                "scrollX":false,
                "scrollY": "30vh",
                "scrollCollapse": true,
    
                "language": {
                    "emptyTable": "No data available"
                },
            });

            init = true;
        }

        connection.cleanup = function () {
            $('#ConnContainer').remove(); 
            init = false;
        }

    } (conndbview.connection = conndbview.connection || {}, jQuery ));
}(window.conndbview = window.conndbview || {}, jQuery ));