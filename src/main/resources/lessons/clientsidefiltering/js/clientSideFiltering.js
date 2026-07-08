var dataFetched = false;

function selectUser() {

    var newEmployeeID = $("#UserSelect").val();
    document.getElementById("employeeRecord").innerHTML = document.getElementById(newEmployeeID).innerHTML;
}

function fetchUserData() {
    if (!dataFetched) {
        dataFetched = true;
        ajaxFunction(document.getElementById("userID").value);
    }
}

function ajaxFunction(userId) {
    $.get("clientSideFiltering/salaries?userId=" + userId, function (result, status) {
        var table = document.createElement("table");
        table.setAttribute("border", "1");
        table.setAttribute("width", "90%");
        table.setAttribute("align", "center");

        var headerRow = document.createElement("tr");
        var headers = ["UserID", "First Name", "Last Name", "SSN", "Salary"];
        for (var h = 0; h < headers.length; h++) {
            var th = document.createElement("td");
            th.textContent = headers[h];
            headerRow.appendChild(th);
        }
        table.appendChild(headerRow);

        for (var i = 0; i < result.length; i++) {
            var row = document.createElement("tr");
            row.id = String(result[i].UserID);

            var userIdCell = document.createElement("td");
            userIdCell.textContent = String(result[i].UserID);
            row.appendChild(userIdCell);

            var firstNameCell = document.createElement("td");
            firstNameCell.textContent = String(result[i].FirstName);
            row.appendChild(firstNameCell);

            var lastNameCell = document.createElement("td");
            lastNameCell.textContent = String(result[i].LastName);
            row.appendChild(lastNameCell);

            var ssnCell = document.createElement("td");
            ssnCell.textContent = String(result[i].SSN);
            row.appendChild(ssnCell);

            var salaryCell = document.createElement("td");
            salaryCell.textContent = String(result[i].Salary);
            row.appendChild(salaryCell);

            table.appendChild(row);
        }

        var newdiv = document.createElement("div");
        newdiv.appendChild(table);
        var container = document.getElementById("hiddenEmployeeRecords");
        container.appendChild(newdiv);
    });
}