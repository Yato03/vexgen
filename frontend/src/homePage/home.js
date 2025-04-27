import React from 'react'
import PropTypes from 'prop-types'
import { useNavigate } from 'react-router-dom'
import Button from '@mui/material/Button'

const HomePage = (props) => {
  const { is_logged } = props
  const navigate = useNavigate()

  const on_button_click = () => {
    navigate('/login')
  }

  return (
    <div className="flex flex-col min-h-screen justify-center items-center m-auto space-y-6 w-11/12 max-w-4xl p-4 overflow-auto">
      <p className="text-3xl md:text-4xl font-extrabold leading-none tracking-tight text-gray-900 text-center">
        Welcome to VEXGen + eGuac!
      </p>
      <p className="text-base md:text-lg text-gray-500 text-center dark:text-gray-400">
        VEXGen is a simple generating tool of VEX files and assisting information supporting the creation of VEX files.
      </p>
      <p className="text-base md:text-lg text-gray-500 text-center dark:text-gray-400">
        Now, with eGuac integration, you can easily ingest your VEX files into the eGuac system and make queries in the GraphQL interface.
      </p>      
      {is_logged ? null : (
        <Button variant="contained" style={{ backgroundColor: "#d97706" }} onClick={on_button_click}>
          Log In
        </Button>
      )}
      <div className="embed-responsive aspect-video">
        <iframe
          title="demo-video"
          className="embed-responsive-item rounded-lg"
          width='853'
          height='480'          
          src="https://www.youtube.com/embed/KPqZaauM2k0"
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
          allowFullScreen
        />
      </div>
    </div>
  )
}

HomePage.propTypes = {
  is_logged: PropTypes.bool
}

export { HomePage }
