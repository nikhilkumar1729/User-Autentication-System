import React from "react";

function Dashboard({ logout }) {

  return (
    <div>
      <h1>Welcome User</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}

export default Dashboard;
