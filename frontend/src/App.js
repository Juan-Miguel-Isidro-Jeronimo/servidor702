import { useEffect, useState } from 'react';

const API_BASE = 'http://127.0.0.1:5000';

function App(){
  const [view, setView] = useState('login');
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [rol, setRol] = useState(localStorage.getItem('rol'));

  useEffect(()=>{
    if(token){
      setView(rol === 'admin' ? 'admin' : 'user');
    }
  },[])

  const handleLogin = async (e)=>{
    e.preventDefault();
    try{
      const form = new FormData(e.target);
      const res = await fetch(API_BASE + '/login', {method:'POST', body: form, mode: 'cors'});
      console.log('fetch status', res.status, res.statusText);
      const text = await res.text();
      try{
        const j = JSON.parse(text);
        if(res.ok){
          localStorage.setItem('token', j.token);
          localStorage.setItem('rol', j.rol);
          setToken(j.token);
          setRol(j.rol);
          setView(j.rol === 'admin' ? 'admin' : 'user');
        } else {
          alert(j.message || j.error || 'Error');
        }
      }catch(err){
        console.error('Respuesta no JSON:', text);
        alert('Respuesta inesperada del servidor. Ver consola.');
      }
    }catch(err){
      console.error('Fetch error:', err);
      alert('Error de red: ' + err.message);
    }
  }

  const handleRegister = async (e)=>{
    e.preventDefault();
    const form = new FormData(e.target);
    const res = await fetch(API_BASE + '/crear_usuario', {method:'POST', body: form});
    const j = await res.json();
    if(res.ok){
      alert('Usuario creado');
      setView('login');
    }else{
      alert(j.error || 'Error');
    }
  }

  if(view === 'login'){
    return (
      <div className="container mt-5">
        <h2>Iniciar sesión</h2>
        <form onSubmit={handleLogin}>
          <div className="mb-3">
            <label className="form-label">Usuario</label>
            <input name="username" className="form-control" />
          </div>
          <div className="mb-3">
            <label className="form-label">Contraseña</label>
            <input type="password" name="password" className="form-control" />
          </div>
          <button className="btn btn-primary">Entrar</button>
          <button type="button" className="btn btn-link" onClick={()=>setView('register')}>Registrarse</button>
        </form>
      </div>
    )
  }

  if(view === 'register'){
    return (
      <div className="container mt-5">
        <h2>Registro</h2>
        <form onSubmit={handleRegister}>
          <div className="mb-3">
            <label className="form-label">Usuario</label>
            <input name="username" className="form-control" />
          </div>
          <div className="mb-3">
            <label className="form-label">Contraseña</label>
            <input type="password" name="password" className="form-control" />
          </div>
          <button className="btn btn-primary">Crear cuenta</button>
          <button type="button" className="btn btn-link" onClick={()=>setView('login')}>Volver</button>
        </form>
      </div>
    )
  }

  if(view === 'admin'){
    return <AdminView token={token} onLogout={()=>{localStorage.removeItem('token'); localStorage.removeItem('rol'); setToken(null); setView('login')}} />
  }

  return <UserView token={token} onLogout={()=>{localStorage.removeItem('token'); localStorage.removeItem('rol'); setToken(null); setView('login')}} />
}

function AdminView({token, onLogout}){
  const [users, setUsers] = useState([]);
  useEffect(()=>{fetchUsers();},[])
  const fetchUsers = async ()=>{
    const res = await fetch('http://localhost:5000/usuarios');
    const j = await res.json();
    if(res.ok) setUsers(j);
  }
  const handleDelete = async (id)=>{
    const res = await fetch(`http://localhost:5000/usuario/${id}`, {method:'DELETE', headers:{'Authorization': 'Bearer '+token}});
    if(res.ok) fetchUsers(); else alert('Error');
  }
  return (
    <div className="container mt-4">
      <div className="d-flex justify-content-between align-items-center">
        <h3>Panel admin</h3>
        <button className="btn btn-secondary" onClick={onLogout}>Cerrar sesión</button>
      </div>
      <table className="table mt-3">
        <thead><tr><th>ID</th><th>Usuario</th><th>Rol</th><th>Acciones</th></tr></thead>
        <tbody>
          {users.map(u=> (
            <tr key={u.id}><td>{u.id}</td><td>{u.username}</td><td>{u.rol || 'usuario'}</td>
              <td>
                <button className="btn btn-sm btn-danger" onClick={()=>handleDelete(u.id)}>Eliminar</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UserView({token, onLogout}){
  const [ventas, setVentas] = useState([]);
  const [username, setUsername] = useState('');
  useEffect(()=>{
    // obtener username desde token o pedir input
  },[])
  const fetchVentas = async ()=>{
    const res = await fetch('http://localhost:5000/obtener_ventas', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body: JSON.stringify({username})});
    const j = await res.json();
    if(res.ok) setVentas(j.ventas || []);
    else alert(j.message || j.error || 'Error');
  }
  return (
    <div className="container mt-4">
      <div className="d-flex justify-content-between align-items-center">
        <h3>Mis ventas</h3>
        <button className="btn btn-secondary" onClick={onLogout}>Cerrar sesión</button>
      </div>
      <div className="mb-3 mt-3">
        <label className="form-label">Tu usuario</label>
        <input className="form-control" value={username} onChange={e=>setUsername(e.target.value)} />
      </div>
      <button className="btn btn-primary mb-3" onClick={fetchVentas}>Cargar ventas</button>
      <div>
        {ventas.length === 0 ? <p>No hay ventas</p> : (
          <ul className="list-group">
            {ventas.map((v,i)=>(<li key={i} className="list-group-item">{v}</li>))}
          </ul>
        )}
      </div>
    </div>
  )
}

export default App;
